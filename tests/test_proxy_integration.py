import asyncio
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from byebyeblock.config import Config
from byebyeblock.metrics import Metrics
from byebyeblock.proxy import ProxyServer


def make_cert(directory):
    cert = Path(directory) / "cert.pem"
    key = Path(directory) / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1",
        "-subj", "/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ], check=True, capture_output=True)
    return cert, key


def _recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        data += chunk
    return data


def _recv_headers(sock):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(1)
        if not chunk:
            raise ConnectionError("connection closed while reading headers")
        data += chunk
    return data


def _read_all(sock):
    data = b""
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    return data


class TestProxyIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cert, self.key = make_cert(self.tmp.name)
        self.server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server_ctx.load_cert_chain(self.cert, self.key)
        self.client_ctx = ssl.create_default_context(cafile=str(self.cert))
        self.tls_server = await asyncio.start_server(self._tls_echo, "127.0.0.1", 0, ssl=self.server_ctx)
        self.tls_port = self.tls_server.sockets[0].getsockname()[1]
        self.http_server = await asyncio.start_server(self._http_echo, "127.0.0.1", 0)
        self.http_port = self.http_server.sockets[0].getsockname()[1]
        self.cfg = Config()
        self.cfg.proxy.allow_private_targets = True
        self.cfg.proxy.allowed_ports = [self.tls_port, self.http_port, 443, 80]
        self.cfg.dns.mode = "system"
        self.cfg.dashboard.enabled = False
        self.cfg.proxy.first_response_timeout = 3
        self.cfg.proxy.connect_timeout = 3
        self.proxy = ProxyServer(self.cfg, Metrics())
        # Bind explicitly to IPv4 loopback so the client never races IPv6 ::1.
        self.cfg.proxy.host = "127.0.0.1"
        self.proxy_host, self.proxy_port = await self.proxy.start()

    async def asyncTearDown(self):
        await self.proxy.stop()
        self.tls_server.close()
        await self.tls_server.wait_closed()
        self.http_server.close()
        await self.http_server.wait_closed()
        self.tmp.cleanup()

    async def _tls_echo(self, reader, writer):
        try:
            data = await reader.read(65536)
            if data:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, ssl.SSLError):
                pass

    async def _http_echo(self, reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    def _tls_via_connect(self):
        # Real blocking client: CONNECT, then TLS over the tunnel, then a request.
        with socket.create_connection((self.proxy_host, self.proxy_port), timeout=5) as raw:
            raw.sendall(f"CONNECT 127.0.0.1:{self.tls_port} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
            resp = _recv_headers(raw)
            if b"200" not in resp.split(b"\r\n", 1)[0]:
                raise AssertionError(f"CONNECT failed: {resp!r}")
            with self.client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                return _read_all(tls)

    def _tls_via_socks(self):
        with socket.create_connection((self.proxy_host, self.proxy_port), timeout=5) as raw:
            raw.sendall(b"\x05\x01\x00")
            if _recv_exact(raw, 2) != b"\x05\x00":
                raise AssertionError("SOCKS5 method negotiation failed")
            raw.sendall(b"\x05\x01\x00\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", self.tls_port))
            reply = _recv_exact(raw, 10)
            if reply[1] != 0:
                raise AssertionError(f"SOCKS5 CONNECT failed: {reply!r}")
            with self.client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                tls.sendall(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                return _read_all(tls)

    async def test_http_connect_tls_direct_and_split(self):
        for strategy in ["direct", "tls-record-sni", "tcp-sni", "tls-record-mid"]:
            with self.subTest(strategy=strategy):
                self.cfg.strategy.mode = "fixed"
                self.cfg.strategy.fixed = strategy
                data = await asyncio.to_thread(self._tls_via_connect)
                self.assertIn(b"200 OK", data)
                self.assertTrue(data.endswith(b"OK"))

    async def test_socks5_tls(self):
        self.cfg.strategy.mode = "fixed"
        self.cfg.strategy.fixed = "tls-record-sni"
        data = await asyncio.to_thread(self._tls_via_socks)
        self.assertIn(b"200 OK", data)
        self.assertTrue(data.endswith(b"OK"))

    async def test_http_absolute_get(self):
        def request():
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=5) as raw:
                raw.sendall(
                    f"GET http://127.0.0.1:{self.http_port}/ HTTP/1.1\r\nHost: 127.0.0.1:{self.http_port}\r\nConnection: close\r\n\r\n".encode()
                )
                return _read_all(raw)

        data = await asyncio.to_thread(request)
        self.assertIn(b"200 OK", data)
        self.assertIn(b"hello", data)

    async def test_private_target_blocked_by_default(self):
        self.cfg.proxy.allow_private_targets = False

        def request():
            with socket.create_connection((self.proxy_host, self.proxy_port), timeout=5) as raw:
                raw.sendall(f"CONNECT 127.0.0.1:{self.tls_port} HTTP/1.1\r\n\r\n".encode())
                return _read_all(raw)

        data = await asyncio.to_thread(request)
        self.assertIn(b"502", data)


if __name__ == "__main__":
    unittest.main()
