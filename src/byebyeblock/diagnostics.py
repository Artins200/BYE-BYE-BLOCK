from __future__ import annotations

import asyncio
import json
import socket
import ssl
import time
from dataclasses import asdict, dataclass, field

from .config import Config
from .dns import Resolver
from .strategies import prepare, send_prepared


@dataclass
class ProbeResult:
    name: str
    ok: bool
    detail: str = ""
    ms: float | None = None
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


async def probe_dns(cfg: Config, host: str) -> list[ProbeResult]:
    results = []
    for mode in ("system", "doh"):
        r = Resolver(cfg.dns, allow_private=True)
        r.cfg.mode = mode
        r.cfg.fallback_system = False
        start = time.perf_counter()
        try:
            res = await r.resolve(host)
            results.append(ProbeResult(f"dns:{mode}", True, ", ".join(res.addresses[:6]), round((time.perf_counter()-start)*1000, 1), {"source": res.source, "addresses": res.addresses}))
        except Exception as exc:  # noqa: BLE001
            results.append(ProbeResult(f"dns:{mode}", False, str(exc), round((time.perf_counter()-start)*1000, 1)))
    return results


async def probe_tcp(host: str, port: int, timeout: float, address: str | None = None) -> ProbeResult:
    start = time.perf_counter()
    try:
        target = address or host
        r, w = await asyncio.wait_for(asyncio.open_connection(target, port), timeout)
        w.close()
        await w.wait_closed()
        return ProbeResult("tcp", True, f"{target}:{port}", round((time.perf_counter()-start)*1000, 1))
    except Exception as exc:  # noqa: BLE001
        return ProbeResult("tcp", False, f"{type(exc).__name__}: {exc}", round((time.perf_counter()-start)*1000, 1))


def _flush(outgoing: ssl.MemoryBIO, writer: asyncio.StreamWriter) -> bytes:
    data = outgoing.read()
    if data:
        writer.write(data)
    return data


async def probe_tls(cfg: Config, host: str, port: int, strategy: str, timeout: float, address: str | None = None, method: str = "HEAD", path: str = "/") -> ProbeResult:
    name = f"tls:{strategy}"
    start = time.perf_counter()
    writer = None
    try:
        target = address or host
        reader, writer = await asyncio.wait_for(asyncio.open_connection(target, port), timeout)
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
        first_flight = True
        ttfb = None
        while True:
            try:
                obj.do_handshake()
                break
            except ssl.SSLWantReadError:
                pass
            out = outgoing.read()
            if out:
                if first_flight:
                    prepared = prepare(out, strategy)
                    await send_prepared(writer, prepared, cfg.strategy.segment_delay_ms)
                    first_flight = False
                else:
                    writer.write(out)
                await writer.drain()
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout)
            except asyncio.TimeoutError:
                return ProbeResult(name, False, "timeout waiting for handshake", round((time.perf_counter()-start)*1000, 1), {"strategy": strategy})
            if not data:
                return ProbeResult(name, False, "connection closed during handshake", round((time.perf_counter()-start)*1000, 1), {"strategy": strategy})
            if ttfb is None:
                ttfb = round((time.perf_counter()-start)*1000, 1)
            incoming.write(data)
        # Handshake complete and certificate verified by OpenSSL.
        req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: byebyeblock-probe/0.1\r\nAccept: */*\r\nConnection: close\r\n\r\n".encode()
        obj.write(req)
        out = outgoing.read()
        writer.write(out)
        await writer.drain()
        response = b""
        body_bytes = 0
        while len(response) < 262144:
            try:
                data = await asyncio.wait_for(reader.read(65536), timeout)
            except asyncio.TimeoutError:
                break
            if not data:
                break
            incoming.write(data)
            try:
                while True:
                    chunk = obj.read(65536)
                    if not chunk:
                        break
                    if not response:
                        response = chunk
                    else:
                        response += chunk
                    body_bytes += len(chunk)
            except ssl.SSLWantReadError:
                pass
            if b"\r\n\r\n" in response and method == "HEAD":
                break
        status = None
        if response.startswith(b"HTTP/"):
            try:
                status = int(response.split(b" ", 2)[1])
            except Exception:
                pass
        ok = status is not None and 200 <= status < 500
        detail = f"HTTP {status}" if status else "TLS ok, no HTTP status"
        return ProbeResult(name, ok, detail, round((time.perf_counter()-start)*1000, 1), {
            "strategy": strategy, "tls": obj.version(), "cipher": obj.cipher()[0] if obj.cipher() else None,
            "status": status, "ttfb_ms": ttfb, "response_bytes": body_bytes, "alpn": obj.selected_alpn_protocol(),
        })
    except ssl.SSLCertVerificationError as exc:
        return ProbeResult(name, False, f"certificate verification failed: {exc.verify_message}", round((time.perf_counter()-start)*1000, 1), {"strategy": strategy, "cert_error": True})
    except ssl.SSLError as exc:
        return ProbeResult(name, False, f"TLS error: {exc}", round((time.perf_counter()-start)*1000, 1), {"strategy": strategy})
    except Exception as exc:  # noqa: BLE001
        return ProbeResult(name, False, f"{type(exc).__name__}: {exc}", round((time.perf_counter()-start)*1000, 1), {"strategy": strategy})
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def run_probe(cfg: Config, host: str, port: int = 443, tls: bool = True, strategies: list[str] | None = None, method: str = "HEAD", path: str = "/") -> dict:
    results: list[ProbeResult] = []
    results.extend(await probe_dns(cfg, host))
    dns_ok = next((r for r in results if r.name == "dns:system" and r.ok), None)
    address = dns_ok.data.get("addresses", [None])[0] if dns_ok else None
    results.append(await probe_tcp(host, port, cfg.proxy.connect_timeout, address))
    if tls:
        for strategy in strategies or ["direct", "tls-record-sni", "tcp-sni", "tls-record-mid"]:
            results.append(await probe_tls(cfg, host, port, strategy, cfg.proxy.connect_timeout, address, method, path))
    return {
        "host": host, "port": port, "tls": tls,
        "results": [r.to_dict() for r in results],
        "summary": {
            "ok": sum(1 for r in results if r.ok),
            "failed": sum(1 for r in results if not r.ok),
            "best_tls_strategy": next((r.data.get("strategy") for r in results if r.ok and r.name.startswith("tls:")), None),
        },
    }
