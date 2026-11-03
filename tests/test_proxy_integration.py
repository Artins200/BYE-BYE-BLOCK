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
        self.cfg.strategy.first_response_timeout = 2
        self.cfg.proxy.first_response_timeout = 2
        self.cfg.proxy.connect_timeout = 2
        self.proxy = ProxyServer(self.cfg, Metrics())
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
        finally:
            writer.close()

    async def _http_echo(self, reader, writer):
        try:
            data = await reader.readuntil(b"\r\n\r\n")
            body = b"hello"
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\n" + body)
            await writer.drain()
        finally:
            writer.close()

    async def test_http_connect_tls_direct_and_split(self):
        for strategy in ["direct", "tls-record-sni", "tcp-sni", "tls-record-mid"]:
            with self.subTest(strategy=strategy):
                self.cfg.strategy.mode = "fixed"
                self.cfg.strategy.fixed = strategy
                reader, writer = await asyncio.open_connection(self.proxy_host, self.proxy_port)
                writer.write(f"CONNECT localhost:{self.tls_port} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
                await writer.drain()
                resp = await reader.readuntil(b"\r\n\r\n")
                self.assertIn(b"200", resp)
                # Upgrade client side to TLS through the proxy tunnel.
                transport = writer.transport
                protocol = transport.get_protocol()
                loop = asyncio.get_running_loop()
                new_transport = await loop.start_tls(transport, protocol, self.client_ctx, server_hostname="localhost")
                # Rebind reader/writer to TLS transport.
                writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)
                reader._transport = new_transport
                writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(65536), 3)
                self.assertIn(b"200 OK", data)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

    async def test_socks5_tls(self):
        self.cfg.strategy.mode = "fixed"
        self.cfg.strategy.fixed = "tls-record-sni"
        reader, writer = await asyncio.open_connection(self.proxy_host, self.proxy_port)
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        self.assertEqual(await reader.readexactly(2), b"\x05\x00")
        host = b"localhost"
        writer.write(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack("!H", self.tls_port))
        await writer.drain()
        reply = await reader.readexactly(10)
        self.assertEqual(reply[1], 0)
        transport = writer.transport
        protocol = transport.get_protocol()
        loop = asyncio.get_running_loop()
        new_transport = await loop.start_tls(transport, protocol, self.client_ctx, server_hostname="localhost")
        writer = asyncio.StreamWriter(new_transport, protocol, reader, loop)
        reader._transport = new_transport
        writer.write(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 3)
        self.assertIn(b"200 OK", data)
        writer.close()

    async def test_http_absolute_get(self):
        reader, writer = await asyncio.open_connection(self.proxy_host, self.proxy_port)
        writer.write(f"GET http://localhost:{self.http_port}/ HTTP/1.1\r\nHost: localhost:{self.http_port}\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 3)
        self.assertIn(b"200 OK", data)
        self.assertIn(b"hello", data)
        writer.close()

    async def test_private_target_blocked_by_default(self):
        self.cfg.proxy.allow_private_targets = False
        reader, writer = await asyncio.open_connection(self.proxy_host, self.proxy_port)
        writer.write(f"CONNECT 127.0.0.1:{self.tls_port} HTTP/1.1\r\n\r\n".encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(65536), 3)
        self.assertIn(b"502", data)
        writer.close()


if __name__ == "__main__":
    unittest.main()
