from __future__ import annotations

import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .config import Config
from .metrics import Metrics

STATIC = Path(__file__).parent / "static"


def demo_metrics() -> Metrics:
    m = Metrics(redact_domains=True)
    m.connections = 1284
    m.active = 7
    m.successes = 1201
    m.failures = 83
    m.bytes_up = 48_233_901
    m.bytes_down = 913_442_120
    m.strategies.update({"direct": 612, "tls-record-sni": 431, "tcp-sni": 122, "http-host-split": 36})
    m.failures_by_reason.update({"timeout": 41, "first-response": 22, "ProxyError": 12, "DNSError": 8})
    hosts = ["h:9f2c1a7b40e1", "h:3b8d0c92aa17", "h:c41e77d0b3f9", "h:0a6d5e81c2b4"]
    strategies = ["direct", "tls-record-sni", "tcp-sni", "http-host-split"]
    for i in range(18):
        m.events.append({
            "ts": round(time.time() - (18-i)*7, 3),
            "kind": "strategy" if i % 3 else "close",
            "host": random.choice(hosts),
            "strategy": random.choice(strategies),
            "reason": "ok" if i % 4 else "timeout",
            "up": random.randint(400, 9000),
            "down": random.randint(2000, 180000),
        })
    return m


class DashboardHandler(BaseHTTPRequestHandler):
    server_version = "BBB-Dashboard/0.2"
    metrics: Metrics
    config: Config
    demo: bool = False

    def log_message(self, fmt, *args):
        pass

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors *")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/status":
            data = self.metrics.snapshot()
            data["demo"] = self.demo
            data["version"] = __version__
            data["proxy"] = {"host": self.config.proxy.host, "port": self.config.proxy.port}
            data["upstream"] = self.config.upstream.mode
            data["dns"] = self.config.dns.mode
            self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json; charset=utf-8")
            return
        if path == "/api/config":
            self._send(200, json.dumps(self.config.to_dict(redact=True), ensure_ascii=False).encode(), "application/json; charset=utf-8")
            return
        if path == "/api/health":
            self._send(200, b'{"ok":true}', "application/json")
            return
        if path == "/":
            path = "/index.html"
        file = (STATIC / path.lstrip("/")).resolve()
        try:
            file.relative_to(STATIC.resolve())
        except ValueError:
            self._send(403, b"forbidden", "text/plain")
            return
        if not file.is_file():
            self._send(404, b"not found", "text/plain")
            return
        ctype = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "application/javascript; charset=utf-8", ".svg": "image/svg+xml"}.get(file.suffix, "application/octet-stream")
        self._send(200, file.read_bytes(), ctype)


def make_server(host: str, port: int, metrics: Metrics, config: Config, demo: bool = False) -> ThreadingHTTPServer:
    handler = type("Handler", (DashboardHandler,), {"metrics": metrics, "config": config, "demo": demo})
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve_dashboard_thread(host: str, port: int, metrics: Metrics, config: Config, demo: bool = False) -> ThreadingHTTPServer:
    server = make_server(host, port, metrics, config, demo)
    t = threading.Thread(target=server.serve_forever, name="bbb-dashboard", daemon=True)
    t.start()
    return server


def serve_dashboard_blocking(host: str, port: int, metrics: Metrics, config: Config, demo: bool = False) -> None:
    if demo:
        metrics = demo_metrics()
    server = make_server(host, port, metrics, config, demo)
    print(f"Dashboard listening on http://{host}:{port} (demo={demo})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
