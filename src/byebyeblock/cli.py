from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
import sys
from pathlib import Path

from . import __version__
from .config import Config, ConfigError, KNOWN_STRATEGIES
from .diagnostics import run_probe
from .metrics import Metrics
from .proxy import ProxyServer


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="bbb", description="BYE-BYE-BLOCK adaptive anti-censorship proxy")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="Start local HTTP/SOCKS5 proxy")
    run.add_argument("--config", type=Path)
    run.add_argument("--host", default=None)
    run.add_argument("--port", type=int, default=None)
    run.add_argument("--no-dashboard", action="store_true")
    run.add_argument("--open-browser", action="store_true", help="Open the local dashboard after startup")
    run.add_argument("--verbose", action="store_true")

    probe = sub.add_parser("probe", help="Diagnose DNS/TCP/TLS and compare strategies")
    probe.add_argument("host")
    probe.add_argument("--port", type=int, default=443)
    probe.add_argument("--no-tls", action="store_true")
    probe.add_argument("--strategies", default="direct,tls-record-sni,tcp-sni,tls-record-mid")
    probe.add_argument("--method", default="HEAD")
    probe.add_argument("--path", default="/")
    probe.add_argument("--config", type=Path)
    probe.add_argument("--json", action="store_true")
    probe.add_argument("--output", type=Path)

    doc = sub.add_parser("doctor", help="Offline environment checks")
    doc.add_argument("--config", type=Path)

    dash = sub.add_parser("dashboard", help="Read-only dashboard")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8787)
    dash.add_argument("--demo", action="store_true", help="Synthetic data; may bind publicly for preview")

    gui = sub.add_parser("gui", help="Start the desktop window (no browser)")
    gui.add_argument("--config", type=Path)
    gui.add_argument("--smoke", action="store_true", help="Open the window briefly and exit (CI)")

    sub.add_parser("config-example", help="Print example TOML config")
    sub.add_parser("strategies", help="List supported strategies")
    return p


def example_config() -> str:
    return """# BYE-BYE-BLOCK local config
[proxy]
host = "127.0.0.1"
port = 8844
max_connections = 256
connect_timeout = 6.0
first_response_timeout = 6.0
idle_timeout = 300.0
allow_private_targets = false
allowed_ports = [80, 443, 8080, 8443]

[dns]
mode = "doh"
providers = ["https://cloudflare-dns.com/dns-query", "https://dns.google/resolve"]
timeout = 3.0
cache_ttl = 300
fallback_system = true

[strategy]
mode = "auto"
order = ["direct", "tls-record-sni", "tcp-sni", "http-host-split"]
fixed = "tls-record-sni"
cache_ttl = 1800
failure_cooldown = 60
segment_delay_ms = 8
tls_retry = true

[upstream]
mode = "none"
host = "127.0.0.1"
port = 1080
remote_dns = true
# username = "user"
# password = "pass"

[dashboard]
enabled = true
host = "127.0.0.1"
port = 8787
redact_domains = true

# Empty domains = apply to all proxied traffic. Example:
# domains = ["*.example.com", "example.org"]
# bypass = ["*.local", "internal.example"]
domains = []
bypass = []
log_domains = false
"""


async def cmd_run(args) -> int:
    cfg = Config.load(args.config)
    if args.host:
        cfg.proxy.host = args.host
    if args.port:
        cfg.proxy.port = args.port
    cfg.validate()
    metrics = Metrics(redact_domains=not cfg.log_domains)
    server = ProxyServer(cfg, metrics)
    host, port = await server.start()
    print(f"Proxy listening on {host}:{port} (HTTP CONNECT + SOCKS5)")
    print("Strategies:", ", ".join(cfg.strategy.order))
    dash_thread = None
    if cfg.dashboard.enabled and not args.no_dashboard:
        from .dashboard import serve_dashboard_thread
        dash_thread = serve_dashboard_thread(cfg.dashboard.host, cfg.dashboard.port, metrics, cfg, demo=False)
        dashboard_url = f"http://{cfg.dashboard.host}:{cfg.dashboard.port}"
        print(f"Dashboard: {dashboard_url}")
        if args.open_browser:
            import webbrowser
            webbrowser.open(dashboard_url)
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    try:
        await stop.wait()
    finally:
        await server.stop()
        if dash_thread:
            dash_thread.shutdown()
    return 0


async def cmd_probe(args) -> int:
    cfg = Config.load(args.config)
    strategies = [s.strip() for s in args.strategies.split(",") if s.strip()]
    for s in strategies:
        if s not in KNOWN_STRATEGIES:
            raise ConfigError(f"Unknown strategy: {s}")
    report = await run_probe(cfg, args.host, args.port, not args.no_tls, strategies, args.method.upper(), args.path)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + "\n", encoding="utf-8")
    if args.json:
        print(text)
    else:
        print(f"Probe {args.host}:{args.port}")
        for r in report["results"]:
            mark = "OK " if r["ok"] else "FAIL"
            ms = f"{r['ms']}ms" if r["ms"] is not None else ""
            print(f"  [{mark}] {r['name']:<22} {ms:<9} {r['detail']}")
        print("Summary:", report["summary"])
    return 0 if report["summary"]["ok"] else 1


def cmd_doctor(args) -> int:
    import ssl
    print("BYE-BYE-BLOCK doctor")
    print(f"  Python: {sys.version.split()[0]}")
    print(f"  OpenSSL: {ssl.OPENSSL_VERSION}")
    ok = sys.version_info >= (3, 11)
    print(f"  Python >= 3.11: {'OK' if ok else 'FAIL'}")
    try:
        cfg = Config.load(args.config)
        cfg.validate()
        print("  Config: OK")
    except Exception as exc:  # noqa: BLE001
        print(f"  Config: FAIL {exc}")
        ok = False
    print("  Note: this tool does not disable TLS certificate verification.")
    print("  Note: UDP/QUIC proxying and kernel packet desync are not implemented in this MVP.")
    return 0 if ok else 1


def cmd_dashboard(args) -> int:
    from .dashboard import serve_dashboard_blocking
    cfg = Config()
    metrics = Metrics()
    serve_dashboard_blocking(args.host, args.port, metrics, cfg, demo=args.demo)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if getattr(args, "verbose", False) else logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    try:
        if args.command == "run":
            return asyncio.run(cmd_run(args))
        if args.command == "probe":
            return asyncio.run(cmd_probe(args))
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "dashboard":
            return cmd_dashboard(args)
        if args.command == "gui":
            from .gui import main as gui_main
            return gui_main(config_path=args.config, smoke=args.smoke)
        if args.command == "config-example":
            print(example_config())
            return 0
        if args.command == "strategies":
            for s in sorted(KNOWN_STRATEGIES):
                print(s)
            return 0
    except ConfigError as exc:
        print(f"Config error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
