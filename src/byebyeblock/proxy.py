from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
import struct
from dataclasses import dataclass
from urllib.parse import urlsplit

from .adaptive import StrategyCache
from .config import Config, in_rules
from .dns import DNSError, Resolver
from .metrics import Metrics
from .strategies import compatible_strategies, detect_protocol, prepare, send_prepared
from .upstream import connect_upstream

log = logging.getLogger(__name__)
MAX_HEADER = 16384
MAX_FIRST = 65536
HOP_HEADERS = {
    b"connection", b"keep-alive", b"proxy-authenticate", b"proxy-authorization",
    b"proxy-connection", b"te", b"trailer", b"transfer-encoding", b"upgrade",
}


class ProxyError(Exception):
    pass


@dataclass
class Target:
    host: str
    port: int
    kind: str  # connect | http | socks
    request: bytes = b""
    method: str = ""


class ProxyServer:
    def __init__(self, cfg: Config, metrics: Metrics | None = None):
        self.cfg = cfg
        self.metrics = metrics or Metrics(redact_domains=not cfg.log_domains)
        self.resolver = Resolver(cfg.dns, allow_private=cfg.proxy.allow_private_targets)
        self.cache = StrategyCache(cfg.strategy.cache_ttl, cfg.strategy.failure_cooldown)
        self.sem = asyncio.Semaphore(cfg.proxy.max_connections)
        self.server: asyncio.Server | None = None

    async def start(self) -> tuple[str, int]:
        self.server = await asyncio.start_server(
            self._handle, self.cfg.proxy.host, self.cfg.proxy.port, limit=MAX_FIRST,
        )
        sock = self.server.sockets[0]
        addr = sock.getsockname()
        return addr[0], addr[1]

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with self.sem:
            self.metrics.begin()
            success = False
            strategy = ""
            reason = ""
            up = down = 0
            host = ""
            try:
                first = await asyncio.wait_for(reader.read(1), self.cfg.proxy.connect_timeout)
                if not first:
                    reason = "empty"
                    return
                if first[0] == 0x05:
                    target = await self._socks_handshake(reader, writer, first)
                else:
                    target = await self._http_handshake(reader, writer, first)
                host = target.host
                self._validate_target(target)
                if target.kind == "connect":
                    writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    await writer.drain()
                    payload = await self._read_first_payload(reader)
                elif target.kind == "socks":
                    writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
                    await writer.drain()
                    payload = await self._read_first_payload(reader)
                else:
                    payload = target.request
                if not payload:
                    reason = "no-payload"
                    return
                up, down, strategy = await self._tunnel(reader, writer, target, payload)
                success = True
            except (ProxyError, DNSError) as exc:
                reason = type(exc).__name__
                self.metrics.event("reject", host=host, reason=str(exc))
                await self._send_error(writer, exc)
            except asyncio.TimeoutError:
                reason = "timeout"
            except (ConnectionError, OSError) as exc:
                reason = getattr(exc, "errno", None) or type(exc).__name__
            except asyncio.IncompleteReadError:
                reason = "eof"
            except Exception as exc:  # noqa: BLE001
                reason = "internal"
                log.exception("proxy internal error: %s", exc)
            finally:
                self.metrics.end(success, strategy, str(reason), up, down)
                if host:
                    self.metrics.event("close", host=host, strategy=strategy, reason="ok" if success else str(reason), up=up, down=down)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    def _validate_target(self, target: Target) -> None:
        if not (1 <= target.port <= 65535):
            raise ProxyError("Invalid port")
        allowed = getattr(self.cfg.proxy, "allowed_ports", None)
        if allowed and target.port not in allowed:
            raise ProxyError("Port not allowed")
        try:
            ip = ipaddress.ip_address(target.host)
            if not self.cfg.proxy.allow_private_targets and not ip.is_global:
                raise ProxyError("Non-public target blocked")
        except ValueError:
            if not target.host or len(target.host) > 253:
                raise ProxyError("Invalid hostname")

    async def _socks_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, first: bytes) -> Target:
        nmethods = (await asyncio.wait_for(reader.readexactly(1), self.cfg.proxy.connect_timeout))[0]
        methods = await asyncio.wait_for(reader.readexactly(nmethods), self.cfg.proxy.connect_timeout)
        if 0x00 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            raise ProxyError("SOCKS5 no-auth required")
        writer.write(b"\x05\x00")
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(4), self.cfg.proxy.connect_timeout)
        if hdr[0] != 0x05 or hdr[1] != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            raise ProxyError("Only SOCKS5 CONNECT is supported")
        atyp = hdr[3]
        if atyp == 0x01:
            host = socket.inet_ntoa(await reader.readexactly(4))
        elif atyp == 0x03:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("idna")
        elif atyp == 0x04:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        else:
            raise ProxyError("Invalid SOCKS5 address type")
        port = struct.unpack("!H", await reader.readexactly(2))[0]
        return Target(host.rstrip("."), port, "socks")

    async def _http_handshake(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, first: bytes) -> Target:
        rest = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), self.cfg.proxy.connect_timeout)
        header = first + rest
        if len(header) > MAX_HEADER:
            raise ProxyError("HTTP header too large")
        lines = header.split(b"\r\n")
        try:
            method, uri, version = lines[0].decode("latin1").split(" ", 2)
        except ValueError as exc:
            raise ProxyError("Bad HTTP request line") from exc
        if version not in {"HTTP/1.0", "HTTP/1.1"}:
            raise ProxyError("Unsupported HTTP version")
        headers: dict[bytes, bytes] = {}
        for line in lines[1:]:
            if not line:
                continue
            if b":" not in line:
                raise ProxyError("Bad HTTP header")
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
        if b"transfer-encoding" in headers:
            raise ProxyError("Chunked proxy requests are not supported")
        if method.upper() == "CONNECT":
            host, port = parse_authority(uri)
            return Target(host, port, "connect", method=method)
        parts = urlsplit(uri)
        if parts.scheme != "http" or not parts.hostname:
            raise ProxyError("Only absolute-form http:// proxy requests are supported")
        host = parts.hostname.rstrip(".")
        port = parts.port or 80
        if parts.username or parts.password or parts.fragment:
            raise ProxyError("Invalid proxy URL")
        host_header = headers.get(b"host", b"").decode("latin1").lower()
        if host_header and parse_authority(host_header)[0] != host.lower():
            raise ProxyError("Host header mismatch")
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        out = [f"{method} {path} {version}".encode("latin1")]
        for line in lines[1:]:
            if not line:
                continue
            k = line.split(b":", 1)[0].strip().lower()
            if k in HOP_HEADERS:
                continue
            out.append(line)
        request = b"\r\n".join(out) + b"\r\n\r\n"
        return Target(host, port, "http", request=request, method=method.upper())

    async def _read_first_payload(self, reader: asyncio.StreamReader) -> bytes:
        data = await asyncio.wait_for(reader.read(MAX_FIRST), self.cfg.proxy.connect_timeout)
        if data and data[0] == 22 and len(data) >= 5:
            need = 5 + int.from_bytes(data[3:5], "big")
            if need > MAX_FIRST:
                raise ProxyError("TLS record too large")
            while len(data) < need:
                chunk = await asyncio.wait_for(reader.readexactly(need - len(data)), self.cfg.proxy.connect_timeout)
                data += chunk
        return data

    async def _tunnel(self, client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter, target: Target, payload: bytes) -> tuple[int, int, str]:
        protocol = detect_protocol(payload)
        direct_only = bool(self.cfg.bypass and in_rules(target.host, self.cfg.bypass)) or bool(self.cfg.domains and not in_rules(target.host, self.cfg.domains))
        if self.cfg.upstream.mode == "socks5":
            resolved = None
            if not self.cfg.upstream.remote_dns:
                resolved = (await self.resolver.resolve(target.host)).addresses[0]
            remote_r, remote_w = await connect_upstream(self.cfg.upstream, target.host, target.port, self.cfg.proxy.connect_timeout, resolved)
            try:
                prepared = prepare(payload, "direct")
                await send_prepared(remote_w, prepared, 0)
                up, down = await self._relay(client_r, client_w, remote_r, remote_w, initial=len(payload))
                self.metrics.event("upstream", host=target.host, strategy="socks5")
                return up, down, "socks5"
            finally:
                remote_w.close()
                try:
                    await remote_w.wait_closed()
                except Exception:
                    pass
        dns = await self.resolver.resolve(target.host)
        if direct_only or self.cfg.strategy.mode == "fixed":
            order = ["direct"] if direct_only else [self.cfg.strategy.fixed]
        else:
            order = self.cache.choose(target.host, target.port, protocol, self.cfg.strategy.order)
        order = compatible_strategies(protocol, order)
        prepared0 = prepare(payload, order[0])
        if not prepared0.safe_to_retry or not self.cfg.strategy.tls_retry:
            order = order[:1]
        last_error = "no-strategy"
        for strategy in order:
            prepared = prepare(payload, strategy)
            for addr in dns.addresses[:3]:
                remote_r = remote_w = None
                try:
                    remote_r, remote_w = await asyncio.wait_for(
                        asyncio.open_connection(addr, target.port, limit=MAX_FIRST),
                        self.cfg.proxy.connect_timeout,
                    )
                    sock = remote_w.get_extra_info("socket")
                    if sock:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    await send_prepared(remote_w, prepared, self.cfg.strategy.segment_delay_ms)
                    first_response = b""
                    if protocol in {"tls", "http"} and prepared.safe_to_retry:
                        try:
                            first_response = await asyncio.wait_for(remote_r.read(MAX_FIRST), self.cfg.proxy.first_response_timeout)
                        except (asyncio.TimeoutError, ConnectionError) as exc:
                            raise ProxyError("first-response") from exc
                        if not first_response:
                            raise ProxyError("first-response-eof")
                        if protocol == "tls" and first_response[0] == 21:
                            raise ProxyError("tls-alert")
                    if protocol in {"tls", "http"} and prepared.safe_to_retry:
                        self.cache.success(target.host, target.port, protocol, strategy)
                    self.metrics.event("strategy", host=target.host, strategy=strategy, protocol=protocol)
                    up, down = await self._relay(client_r, client_w, remote_r, remote_w, initial=len(payload), pre_received=first_response)
                    return up, down, strategy
                except (ProxyError, asyncio.TimeoutError, ConnectionError, OSError) as exc:
                    last_error = str(exc) or type(exc).__name__
                    if protocol in {"tls", "http"} and prepared.safe_to_retry:
                        self.cache.failure(target.host, target.port, protocol, strategy)
                    if remote_w:
                        remote_w.close()
                        try:
                            await remote_w.wait_closed()
                        except Exception:
                            pass
                    continue
        raise ProxyError(f"All strategies failed: {last_error}")

    async def _relay(self, client_r, client_w, remote_r, remote_w, initial: int = 0, pre_received: bytes = b"") -> tuple[int, int]:
        up = initial
        down = 0
        if pre_received:
            client_w.write(pre_received)
            await client_w.drain()
            down += len(pre_received)

        async def pump(src, dst, direction):
            nonlocal up, down
            while True:
                data = await asyncio.wait_for(src.read(MAX_FIRST), self.cfg.proxy.idle_timeout)
                if not data:
                    try:
                        if dst.can_write_eof():
                            dst.write_eof()
                    except (OSError, NotImplementedError):
                        pass
                    break
                dst.write(data)
                await dst.drain()
                if direction == "up":
                    up += len(data)
                else:
                    down += len(data)

        t1 = asyncio.create_task(pump(client_r, remote_w, "up"))
        t2 = asyncio.create_task(pump(remote_r, client_w, "down"))
        try:
            await asyncio.gather(t1, t2)
        except Exception:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            raise
        return up, down

    async def _send_error(self, writer: asyncio.StreamWriter, exc: Exception) -> None:
        try:
            msg = str(exc)[:120].encode("utf-8", "replace")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: " + str(len(msg)).encode() + b"\r\n\r\n" + msg)
            await writer.drain()
        except Exception:
            pass


def parse_authority(value: str) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        end = value.find("]")
        if end == -1:
            raise ProxyError("Bad IPv6 authority")
        host = value[1:end]
        rest = value[end+1:]
        port = 443
        if rest:
            if not rest.startswith(":"):
                raise ProxyError("Bad IPv6 authority")
            port = int(rest[1:])
        return host, port
    if ":" in value:
        host, p = value.rsplit(":", 1)
        if not p.isdigit():
            raise ProxyError("Bad port")
        return host, int(p)
    return value, 443
