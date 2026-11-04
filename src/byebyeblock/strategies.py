from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import BinaryIO

TLS_HANDSHAKE = 22
CLIENT_HELLO = 1
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"CONNECT ", b"PATCH ", b"TRACE ")


@dataclass
class ClientHello:
    sni: str | None
    sni_offset: int | None  # offset of SNI value inside TLS record payload
    record_end: int
    has_early_data: bool
    record_version: bytes


@dataclass
class Prepared:
    strategy: str
    protocol: str
    chunks: list[bytes]
    safe_to_retry: bool
    sni: str | None = None


def parse_client_hello(data: bytes) -> ClientHello | None:
    if len(data) < 6 or data[0] != TLS_HANDSHAKE:
        return None
    rec_len = int.from_bytes(data[3:5], "big")
    end = 5 + rec_len
    if rec_len < 4 or len(data) < end:
        return None
    p = data[5:end]
    if p[0] != CLIENT_HELLO:
        return None
    hs_len = int.from_bytes(p[1:4], "big")
    if hs_len + 4 > len(p):
        # ClientHello spans multiple records; caller can use tcp-mid.
        return ClientHello(None, None, end, False, data[1:3])
    try:
        i = 4 + 2 + 32
        sid_len = p[i]; i += 1 + sid_len
        cs_len = int.from_bytes(p[i:i+2], "big"); i += 2 + cs_len
        comp_len = p[i]; i += 1 + comp_len
        if i + 2 > len(p):
            return ClientHello(None, None, end, False, data[1:3])
        ext_len = int.from_bytes(p[i:i+2], "big"); i += 2
        ext_end = min(i + ext_len, len(p))
        sni = None; sni_off = None; early = False
        while i + 4 <= ext_end:
            et = int.from_bytes(p[i:i+2], "big")
            el = int.from_bytes(p[i+2:i+4], "big")
            body = p[i+4:i+4+el]
            if i + 4 + el > ext_end:
                break
            if et == 42:
                early = True
            if et == 0 and len(body) >= 5:
                list_len = int.from_bytes(body[0:2], "big")
                j = 2
                if j + 3 <= 2 + list_len and body[j] == 0:
                    n = int.from_bytes(body[j+1:j+3], "big")
                    val = body[j+3:j+3+n]
                    if len(val) == n:
                        sni = val.decode("ascii", errors="replace")
                        sni_off = 5 + i + 4 + j + 3
            i += 4 + el
        return ClientHello(sni, sni_off, end, early, data[1:3])
    except (IndexError, ValueError):
        return ClientHello(None, None, end, False, data[1:3])


def is_tls(data: bytes) -> bool:
    return len(data) >= 3 and data[0] == TLS_HANDSHAKE and data[1] == 3


def is_http(data: bytes) -> bool:
    return any(data.startswith(m) for m in HTTP_METHODS)


def split_tls_record(data: bytes, pos: int) -> list[bytes]:
    """Split one TLS record into two valid records without changing handshake bytes."""
    ch = parse_client_hello(data)
    if not ch or not (5 < pos < ch.record_end):
        return [data]
    payload = data[5:ch.record_end]
    pos -= 5
    if not (0 < pos < len(payload)):
        return [data]
    hdr = data[0:3]
    a = hdr + pos.to_bytes(2, "big") + payload[:pos]
    b = hdr + (len(payload) - pos).to_bytes(2, "big") + payload[pos:]
    rest = data[ch.record_end:]
    return [a, b] + ([rest] if rest else [])


def prepare(data: bytes, strategy: str) -> Prepared:
    if strategy == "direct" or not data:
        return Prepared("direct", detect_protocol(data), [data], True, parse_sni(data))
    if is_tls(data):
        ch = parse_client_hello(data)
        sni = ch.sni if ch else None
        safe = bool(ch and not ch.has_early_data and ch.record_end == len(data) and ch.sni_offset)
        if strategy in {"tls-record-sni", "tls-record-mid"}:
            if ch and ch.sni_offset and strategy == "tls-record-sni":
                # Split inside the hostname value.
                name_len = len((ch.sni or "").encode())
                pos = ch.sni_offset + max(1, name_len // 2)
            elif ch:
                pos = 5 + max(6, (ch.record_end - 5) // 2)
            else:
                pos = max(6, len(data) // 2)
            chunks = split_tls_record(data, pos)
            return Prepared(strategy if len(chunks) > 1 else "direct", "tls", chunks, safe, sni)
        if strategy in {"tcp-sni", "tcp-mid"}:
            if ch and ch.sni_offset and strategy == "tcp-sni":
                pos = ch.sni_offset + max(1, len((ch.sni or "").encode()) // 2)
            else:
                pos = max(1, len(data) // 2)
            pos = min(max(1, pos), len(data) - 1) if len(data) > 1 else 1
            chunks = [data[:pos], data[pos:]] if 0 < pos < len(data) else [data]
            return Prepared(strategy if len(chunks) > 1 else "direct", "tls", chunks, safe, sni)
        return Prepared("direct", "tls", [data], safe, sni)
    if is_http(data):
        safe = data.startswith((b"GET ", b"HEAD ", b"OPTIONS ", b"TRACE "))
        if strategy == "http-host-split":
            m = re.search(rb"\r\nHost:\s*([^\r\n]+)\r\n", data, re.IGNORECASE)
            if m:
                start, end = m.span(1)
                pos = start + max(1, (end - start) // 2)
                return Prepared(strategy, "http", [data[:pos], data[pos:]], safe)
        if strategy == "tcp-mid" and len(data) > 1:
            pos = len(data) // 2
            return Prepared(strategy, "http", [data[:pos], data[pos:]], safe)
        if strategy == "http-header-case":
            changed = re.sub(rb"\r\nHost:", b"\r\nhOsT:", data, count=1, flags=re.IGNORECASE)
            return Prepared(strategy if changed != data else "direct", "http", [changed], safe)
        return Prepared("direct", "http", [data], safe)
    if strategy == "tcp-mid" and len(data) > 1:
        pos = len(data) // 2
        return Prepared(strategy, detect_protocol(data), [data[:pos], data[pos:]], False, None)
    return Prepared("direct", detect_protocol(data), [data], False, None)


def detect_protocol(data: bytes) -> str:
    if is_tls(data):
        return "tls"
    if is_http(data):
        return "http"
    return "tcp"


def parse_sni(data: bytes) -> str | None:
    ch = parse_client_hello(data)
    return ch.sni if ch else None


def compatible_strategies(protocol: str, order: list[str]) -> list[str]:
    out: list[str] = []
    for s in order:
        if protocol == "tls" and s in {"direct", "tls-record-sni", "tls-record-mid", "tcp-sni", "tcp-mid"}:
            out.append(s)
        elif protocol == "http" and s in {"direct", "http-host-split", "http-header-case", "tcp-mid"}:
            out.append(s)
        elif protocol == "tcp" and s == "direct":
            out.append(s)
    if "direct" not in out:
        out.append("direct")
    return out or ["direct"]


async def send_prepared(writer: asyncio.StreamWriter, prepared: Prepared, delay_ms: int) -> None:
    sock = writer.get_extra_info("socket")
    if sock is not None:
        try:
            import socket
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
    for i, chunk in enumerate(prepared.chunks):
        if not chunk:
            continue
        writer.write(chunk)
        await writer.drain()
        if i + 1 < len(prepared.chunks) and delay_ms:
            await asyncio.sleep(delay_ms / 1000)
