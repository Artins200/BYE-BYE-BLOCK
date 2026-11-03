import tempfile
import time
import unittest
from pathlib import Path

from byebyeblock.config import Config, ConfigError, domain_matches, in_rules
from byebyeblock.adaptive import StrategyCache


class TestConfig(unittest.TestCase):
    def test_defaults_valid(self):
        Config().validate()

    def test_reject_public_proxy(self):
        cfg = Config()
        cfg.proxy.host = "0.0.0.0"
        with self.assertRaises(ConfigError):
            cfg.validate()

    def test_reject_public_dashboard(self):
        cfg = Config()
        cfg.dashboard.host = "0.0.0.0"
        with self.assertRaises(ConfigError):
            cfg.validate()

    def test_unknown_strategy(self):
        cfg = Config()
        cfg.strategy.order = ["magic"]
        with self.assertRaises(ConfigError):
            cfg.validate()

    def test_toml_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "c.toml"
            p.write_text('[proxy]\nport = 9999\n[strategy]\norder = ["direct", "tcp-sni"]\n')
            cfg = Config.load(p)
            self.assertEqual(cfg.proxy.port, 9999)
            self.assertEqual(cfg.strategy.order, ["direct", "tcp-sni"])

    def test_domain_rules(self):
        self.assertTrue(domain_matches("a.example.com", "*.example.com"))
        self.assertTrue(domain_matches("example.com", "*.example.com"))
        self.assertFalse(domain_matches("badexample.com", "*.example.com"))
        self.assertTrue(in_rules("x.y.example.org", ["*.example.org"]))


class TestAdaptive(unittest.TestCase):
    def test_preferred_first(self):
        c = StrategyCache()
        c.success("h", 443, "tls", "tcp-sni")
        self.assertEqual(c.choose("h", 443, "tls", ["direct", "tcp-sni"])[0], "tcp-sni")

    def test_failure_cooldown(self):
        c = StrategyCache(cooldown=60)
        c.failure("h", 443, "tls", "direct")
        order = c.choose("h", 443, "tls", ["direct", "tcp-sni"])
        self.assertEqual(order[0], "tcp-sni")

    def test_all_failed_still_returns(self):
        c = StrategyCache(cooldown=60)
        c.failure("h", 443, "tls", "direct")
        c.failure("h", 443, "tls", "tcp-sni")
        self.assertTrue(c.choose("h", 443, "tls", ["direct", "tcp-sni"]))


if __name__ == "__main__":
    unittest.main()
