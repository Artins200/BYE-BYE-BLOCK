from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .config import DnsConfig


class DNSError(Exception):
    pass


@dataclass
class DNSResult:
    addresses: list[str]
    source: str
    ttl: int = 0


class Resolver:
    def __init__(self, cfg: DnsConfig, allow_private: bool = False):
        self.cfg = cfg
        self.allow_private = allow_private
        self._cache: dict[str, tuple[float, DNSResult]] = {}
        self._lock = asyncio.Lock()

    async def resolve(self, host: str) -> DNSResult:
        try:
            ip = ipaddress.ip_address(host)
            self._check_ip(str(ip))
            return DNSResult([str(ip)], "literal")
        except ValueError:
            pass
        host = host.rstrip(".").lower()
        if not host or len(host) > 253 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
            raise DNSError("Invalid hostname")
        now = time.monotonic()
        cached = self._cache.get(host)
        if cached and cached[0] > now:
            return cached[1]
        async with self._lock:
            cached = self._cache.get(host)
            if cached and cached[0] > now:
                return cached[1]
            result: DNSResult | None = None
            errors: list[str] = []
            if self.cfg.mode == "doh":
                for provider in self.cfg.providers:
                    try:
                        result = await asyncio.to_thread(self._doh_query, provider, host)
                        break
                    except Exception as exc:  # noqa: BLE001 - report and try next provider
                        errors.append(f"{provider}: {exc}")
                if result is None and self.cfg.fallback_system:
                    try:
                        result = await self._system(host)
                        result.source = "system-fallback"
                    except Exception as exc:  # noqa: BLE001
                        errors.append(f"system: {exc}")
            else:
                result = await self._system(host)
            if result is None or not result.addresses:
                raise DNSError("; ".join(errors) or "No addresses")
            for addr in result.addresses:
                self._check_ip(addr)
            ttl = max(5, min(result.ttl or self.cfg.cache_ttl, self.cfg.cache_ttl))
            self._cache[host] = (now + ttl, result)
            if len(self._cache) > 4096:
                self._cache = {k: v for k, v in self._cache.items() if v[0] > now}
            return result

    def _check_ip(self, addr: str) -> None:
        ip = ipaddress.ip_address(addr)
        if not self.allow_private and not ip.is_global:
            raise DNSError(f"Blocked non-public address: {addr}")

    async def _system(self, host: str) -> DNSResult:
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise DNSError(str(exc)) from exc
        addrs: list[str] = []
        for info in infos:
            addr = info[4][0]
            if addr not in addrs:
                addrs.append(addr)
        if not addrs:
            raise DNSError("No addresses")
        return DNSResult(addrs, "system")

    def _doh_query(self, provider: str, host: str) -> DNSResult:
        addrs: list[str] = []
        ttl = self.cfg.cache_ttl
        for qtype in ("A", "AAAA"):
            url = provider + ("&" if "?" in provider else "?") + urllib.parse.urlencode({"name": host, "type": qtype})
            req = urllib.request.Request(url, headers={"Accept": "application/dns-json", "User-Agent": "byebyeblock/0.1"})
            with urllib.request.urlopen(req, timeout=self.cfg.timeout) as resp:
                raw = resp.read(1_000_000)
            data = json.loads(raw.decode("utf-8"))
            if data.get("Status") not in (0, None):
                continue
            for ans in data.get("Answer", []):
                if ans.get("type") == 1 and qtype == "A" or ans.get("type") == 28 and qtype == "AAAA":
                    addr = ans.get("data")
                    try:
                        ipaddress.ip_address(addr)
                    except ValueError:
                        continue
                    if addr not in addrs:
                        addrs.append(addr)
                    ttl = min(ttl, int(ans.get("TTL", ttl)))
        if not addrs:
            raise DNSError("DoH returned no A/AAAA records")
        return DNSResult(addrs, "doh", ttl)

    def clear(self) -> None:
        self._cache.clear()
