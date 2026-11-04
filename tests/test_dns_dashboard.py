import json
import unittest
from unittest.mock import patch

from byebyeblock.config import Config
from byebyeblock.dns import Resolver, DNSError
from byebyeblock.dashboard import make_server, demo_metrics
from byebyeblock.metrics import Metrics


class TestDNS(unittest.IsolatedAsyncioTestCase):
    async def test_literal_private_blocked(self):
        r = Resolver(Config().dns, allow_private=False)
        with self.assertRaises(DNSError):
            await r.resolve("127.0.0.1")

    async def test_literal_public_ok(self):
        r = Resolver(Config().dns, allow_private=False)
        res = await r.resolve("1.1.1.1")
        self.assertEqual(res.addresses, ["1.1.1.1"])

    async def test_doh_mock(self):
        cfg = Config().dns
        cfg.mode = "doh"
        r = Resolver(cfg, allow_private=False)
        fake = {"Status": 0, "Answer": [{"type": 1, "data": "93.184.216.34", "TTL": 60}]}
        class Resp:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n): return json.dumps(fake).encode()
        with patch("urllib.request.urlopen", return_value=Resp()):
            res = await r.resolve("example.com")
        self.assertEqual(res.addresses, ["93.184.216.34"])
        self.assertEqual(res.source, "doh")


class TestDashboard(unittest.TestCase):
    def test_demo_status(self):
        server = make_server("127.0.0.1", 0, demo_metrics(), Config(), demo=True)
        import threading, urllib.request
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            port = server.server_address[1]
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/status") as resp:
                data = json.loads(resp.read())
            self.assertTrue(data["demo"])
            self.assertGreater(data["connections"], 0)
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
                self.assertIn(b"BYE-BYE-BLOCK", resp.read())
        finally:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    unittest.main()
