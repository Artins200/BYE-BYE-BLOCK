from __future__ import annotations

import asyncio
import ipaddress
import socket
import struct

from .config import UpstreamConfig


class UpstreamError(Exception):
    pass


async def connect_upstream(cfg: UpstreamConfig, host: str, port: int, timeout: float, resolved_ip: str | None = None) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    if cfg.mode != "socks5":
        raise UpstreamError("Upstream is not enabled")
    reader, writer = await asyncio.wait_for(asyncio.open_connection(cfg.host, cfg.port), timeout)
    try:
        methods = [0x00]
        if cfg.username is not None:
            methods.append(0x02)
        writer.write(bytes([0x05, len(methods), *methods]))
        await writer.drain()
        hdr = await asyncio.wait_for(reader.readexactly(2), timeout)
        if hdr[0] != 0x05 or hdr[1] not in methods:
            raise UpstreamError("SOCKS5 method negotiation failed")
        if hdr[1] == 0x02:
            user = (cfg.username or "").encode()
            pwd = (cfg.password or "").encode()
            if len(user) > 255 or len(pwd) > 255:
                raise UpstreamError("SOCKS5 credentials too long")
            writer.write(bytes([0x01, len(user)]) + user + bytes([len(pwd)]) + pwd)
            await writer.drain()
            auth = await asyncio.wait_for(reader.readexactly(2), timeout)
            if auth != b"\x01\x00":
                raise UpstreamError("SOCKS5 authentication failed")
        target = host if cfg.remote_dns or resolved_ip is None else resolved_ip
        try:
            ip = ipaddress.ip_address(target)
            if ip.version == 4:
                addr = bytes([0x01]) + ip.packed
            else:
                addr = bytes([0x04]) + ip.packed
        except ValueError:
            raw = target.encode("idna")
            if len(raw) > 255:
                raise UpstreamError("Hostname too long")
            addr = bytes([0x03, len(raw)]) + raw
        writer.write(b"\x05\x01\x00" + addr + struct.pack("!H", port))
        await writer.drain()
        reply = await asyncio.wait_for(reader.readexactly(4), timeout)
        if reply[0] != 0x05 or reply[1] != 0x00:
            raise UpstreamError(f"SOCKS5 CONNECT failed: {reply[1]:#x}")
        atyp = reply[3]
        if atyp == 0x01:
            await reader.readexactly(4 + 2)
        elif atyp == 0x04:
            await reader.readexactly(16 + 2)
        elif atyp == 0x03:
            n = (await reader.readexactly(1))[0]
            await reader.readexactly(n + 2)
        else:
            raise UpstreamError("Invalid SOCKS5 reply")
        sock = writer.get_extra_info("socket")
        if sock:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        return reader, writer
    except Exception:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        raise
