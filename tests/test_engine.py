import socket
import unittest

from byebyeblock.config import Config
from byebyeblock.engine import Engine


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_cfg(port: int) -> Config:
    cfg = Config()
    cfg.proxy.port = port
    cfg.dns.mode = "system"
    cfg.dashboard.enabled = False
    return cfg


class TestEngine(unittest.TestCase):
    def test_start_stop(self):
        engine = Engine(make_cfg(free_port()))
        host, port = engine.start()
        try:
            self.assertTrue(engine.running)
            self.assertEqual(host, "127.0.0.1")
            with socket.create_connection((host, port), timeout=3) as s:
                s.sendall(b"\x05\x01\x00")
                self.assertEqual(s.recv(2), b"\x05\x00")
        finally:
            engine.stop()
        self.assertFalse(engine.running)
        self.assertIsNone(engine.bound)

    def test_restart(self):
        engine = Engine(make_cfg(free_port()))
        engine.start()
        engine.stop()
        engine.start()
        engine.stop()
        self.assertFalse(engine.running)

    def test_port_conflict_raises(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            s.listen(1)
            port = s.getsockname()[1]
            engine = Engine(make_cfg(port))
            with self.assertRaises(OSError):
                engine.start()
            self.assertFalse(engine.running)

    def test_double_start_raises(self):
        engine = Engine(make_cfg(free_port()))
        engine.start()
        try:
            with self.assertRaises(RuntimeError):
                engine.start()
        finally:
            engine.stop()


if __name__ == "__main__":
    unittest.main()
