import sys
import unittest

from byebyeblock import winproxy


class TestWinProxy(unittest.TestCase):
    def test_supported_matches_platform(self):
        self.assertEqual(winproxy.supported(), sys.platform == "win32")

    def test_restore_without_apply_is_safe(self):
        winproxy.restore()
        self.assertIsNone(winproxy._STATE)

    @unittest.skipIf(sys.platform == "win32", "non-Windows guard")
    def test_apply_unsupported_raises(self):
        with self.assertRaises(RuntimeError):
            winproxy.apply("127.0.0.1", 8844)


if __name__ == "__main__":
    unittest.main()
