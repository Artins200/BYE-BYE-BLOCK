from __future__ import annotations

import ipaddress
import tomllib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

DEFAULT_STRATEGIES = ["direct", "tls-record-sni", "tcp-sni", "http-host-split"]
KNOWN_STRATEGIES = {
    "direct", "tls-record-sni", "tls-record-mid", "tcp-sni", "tcp-mid",
    "http-host-split", "http-header-case",
}


class ConfigError(ValueError):
    pass


@dataclass
class ProxyConfig:
    host: str = "127.0.0.1"
    port: int = 8844
    max_connections: int = 256
    connect_timeout: float = 6.0
    first_response_timeout: float = 6.0
    idle_timeout: float = 300.0
    allow_private_targets: bool = False
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443, 8080, 8443])


@dataclass
class DnsConfig:
    mode: str = "doh"  # doh | system
    providers: list[str] = field(default_factory=lambda: [
        "https://cloudflare-dns.com/dns-query",
        "https://dns.google/resolve",
    ])
    timeout: float = 3.0
    cache_ttl: int = 300
    fallback_system: bool = True


@dataclass
class StrategyConfig:
    mode: str = "auto"  # auto | fixed
    order: list[str] = field(default_factory=lambda: list(DEFAULT_STRATEGIES))
    fixed: str = "tls-record-sni"
    cache_ttl: int = 1800
    failure_cooldown: int = 60
    segment_delay_ms: int = 8
    tls_retry: bool = True


@dataclass
class UpstreamConfig:
    mode: str = "none"  # none | socks5
    host: str = "127.0.0.1"
    port: int = 1080
    username: str | None = None
    password: str | None = None
    remote_dns: bool = True


@dataclass
class DashboardConfig:
    enabled: bool = True
    host: str = "127.0.0.1"
    port: int = 8787
    redact_domains: bool = True


@dataclass
class Config:
    proxy: ProxyConfig = field(default_factory=ProxyConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    strategy: StrategyConfig = field(default_factory=StrategyConfig)
    upstream: UpstreamConfig = field(default_factory=UpstreamConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)
    domains: list[str] = field(default_factory=list)
    bypass: list[str] = field(default_factory=list)
    log_domains: bool = False

    @classmethod
    def load(cls, path: str | Path | None) -> "Config":
        cfg = cls()
        if path is None:
            return cfg
        p = Path(path)
        if not p.exists():
            raise ConfigError(f"Config not found: {p}")
        with p.open("rb") as f:
            raw = tomllib.load(f)
        section_map = {
            "proxy": (cfg.proxy, ProxyConfig),
            "dns": (cfg.dns, DnsConfig),
            "strategy": (cfg.strategy, StrategyConfig),
            "upstream": (cfg.upstream, UpstreamConfig),
            "dashboard": (cfg.dashboard, DashboardConfig),
        }
        for key, value in raw.items():
            if key in section_map:
                obj, _ = section_map[key]
                if not isinstance(value, dict):
                    raise ConfigError(f"[{key}] must be a table")
                for k, v in value.items():
                    if not hasattr(obj, k):
                        raise ConfigError(f"Unknown option [{key}].{k}")
                    setattr(obj, k, v)
            elif hasattr(cfg, key) and key not in section_map:
                setattr(cfg, key, value)
            else:
                raise ConfigError(f"Unknown option: {key}")
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if not is_loopback(self.proxy.host):
            raise ConfigError("proxy.host must be loopback; this MVP is not an open LAN proxy")
        check_port(self.proxy.port, "proxy.port")
        check_port(self.dashboard.port, "dashboard.port")
        for port in self.proxy.allowed_ports:
            check_port(port, "proxy.allowed_ports")
        if self.proxy.max_connections < 1:
            raise ConfigError("proxy.max_connections must be >= 1")
        for name in ("connect_timeout", "first_response_timeout", "idle_timeout"):
            if float(getattr(self.proxy, name)) <= 0:
                raise ConfigError(f"proxy.{name} must be > 0")
        if self.dns.mode not in {"doh", "system"}:
            raise ConfigError("dns.mode must be doh or system")
        if self.dns.mode == "doh" and not self.dns.providers:
            raise ConfigError("dns.providers cannot be empty in doh mode")
        for url in self.dns.providers:
            if not url.startswith("https://"):
                raise ConfigError("DoH providers must use https://")
        if self.strategy.mode not in {"auto", "fixed"}:
            raise ConfigError("strategy.mode must be auto or fixed")
        for s in self.strategy.order + [self.strategy.fixed]:
            if s not in KNOWN_STRATEGIES:
                raise ConfigError(f"Unknown strategy: {s}")
        if not self.strategy.order:
            raise ConfigError("strategy.order cannot be empty")
        if self.strategy.segment_delay_ms < 0:
            raise ConfigError("strategy.segment_delay_ms must be >= 0")
        if self.upstream.mode not in {"none", "socks5"}:
            raise ConfigError("upstream.mode must be none or socks5")
        check_port(self.upstream.port, "upstream.port")
        if self.upstream.mode == "socks5" and (self.upstream.username is None) != (self.upstream.password is None):
            raise ConfigError("upstream username and password must be set together")
        if self.dashboard.enabled and not is_loopback(self.dashboard.host):
            raise ConfigError("dashboard.host must be loopback; use `bbb dashboard --demo` for a public read-only preview")

    def to_dict(self, redact: bool = True) -> dict[str, Any]:
        d = asdict(self)
        if redact and d["upstream"].get("password"):
            d["upstream"]["password"] = "***"
        if redact and d["upstream"].get("username"):
            d["upstream"]["username"] = "***"
        return d


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def check_port(port: int, name: str) -> None:
    if not isinstance(port, int) or not (1 <= port <= 65535):
        raise ConfigError(f"{name} must be an integer in 1..65535")


def domain_matches(host: str, rule: str) -> bool:
    host = host.rstrip(".").lower()
    rule = rule.rstrip(".").lower()
    if rule.startswith("*."):
        base = rule[2:]
        return host == base or host.endswith("." + base)
    return host == rule


def in_rules(host: str, rules: list[str]) -> bool:
    return any(domain_matches(host, r) for r in rules)
