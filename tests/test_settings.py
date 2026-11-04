import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from byebyeblock import gui


def settings_env(directory: str) -> dict:
    if sys.platform == "win32":
        return {"APPDATA": directory}
    if sys.platform == "darwin":
        return {"HOME": directory}
    return {"XDG_CONFIG_HOME": directory}


class TestSettings(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, settings_env(d)):
                gui.save_settings({"port": 9999, "dns_mode": "system"})
                data = gui.load_settings()
        self.assertEqual(data["port"], 9999)
        self.assertEqual(data["dns_mode"], "system")

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, settings_env(d)):
                self.assertEqual(gui.load_settings(), {})

    def test_corrupt_file(self):
        with tempfile.TemporaryDirectory() as d:
            with patch.dict(os.environ, settings_env(d)):
                path = gui.settings_dir() / "settings.json"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("{not json", encoding="utf-8")
                self.assertEqual(gui.load_settings(), {})


class TestGuiHelpers(unittest.TestCase):
    def test_human_bytes(self):
        self.assertEqual(gui.human_bytes(0), "0 B")
        self.assertEqual(gui.human_bytes(1024), "1.0 KB")
        self.assertTrue(gui.human_bytes(5 * 1024 * 1024).endswith("MB"))

    def test_build_config(self):
        cfg = gui.build_config(8844, "doh", False, 1080)
        self.assertEqual(cfg.proxy.port, 8844)
        self.assertFalse(cfg.dashboard.enabled)
        self.assertEqual(cfg.upstream.mode, "none")
        cfg = gui.build_config(9000, "system", True, 1081)
        self.assertEqual(cfg.upstream.mode, "socks5")
        self.assertEqual(cfg.upstream.port, 1081)


if __name__ == "__main__":
    unittest.main()
