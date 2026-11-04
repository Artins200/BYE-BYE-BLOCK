import ssl
import unittest

from byebyeblock.strategies import parse_client_hello, prepare, split_tls_record, compatible_strategies


def client_hello(host="example.com"):
    ctx = ssl.create_default_context()
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


class TestStrategies(unittest.TestCase):
    def test_parse_sni(self):
        data = client_hello("example.com")
        ch = parse_client_hello(data)
        self.assertIsNotNone(ch)
        self.assertEqual(ch.sni, "example.com")
        self.assertIsNotNone(ch.sni_offset)
        self.assertEqual(data[ch.sni_offset:ch.sni_offset+len("example.com")], b"example.com")

    def test_tls_record_split_reassembles(self):
        data = client_hello("www.example.org")
        ch = parse_client_hello(data)
        pos = ch.sni_offset + 3
        chunks = split_tls_record(data, pos)
        self.assertEqual(len(chunks), 2)
        payload = b"".join(c[5:] for c in chunks)
        self.assertEqual(payload, data[5:])
        for c in chunks:
            self.assertEqual(c[0], 22)
            self.assertEqual(int.from_bytes(c[3:5], "big"), len(c) - 5)

    def test_prepare_tls_record_sni(self):
        data = client_hello("example.com")
        p = prepare(data, "tls-record-sni")
        self.assertEqual(p.protocol, "tls")
        self.assertEqual(p.strategy, "tls-record-sni")
        self.assertTrue(p.safe_to_retry)
        self.assertEqual(b"".join(c[5:] for c in p.chunks), data[5:])

    def test_prepare_tcp_sni(self):
        data = client_hello("example.com")
        p = prepare(data, "tcp-sni")
        self.assertEqual(p.strategy, "tcp-sni")
        self.assertEqual(b"".join(p.chunks), data)

    def test_http_host_split(self):
        data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        p = prepare(data, "http-host-split")
        self.assertEqual(p.strategy, "http-host-split")
        self.assertEqual(b"".join(p.chunks), data)
        self.assertTrue(p.safe_to_retry)

    def test_post_not_safe(self):
        data = b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 0\r\n\r\n"
        p = prepare(data, "http-host-split")
        self.assertFalse(p.safe_to_retry)

    def test_compatible(self):
        self.assertIn("tls-record-sni", compatible_strategies("tls", ["tls-record-sni", "http-host-split"]))
        self.assertNotIn("http-host-split", compatible_strategies("tls", ["http-host-split"]))
        self.assertIn("direct", compatible_strategies("tcp", ["tls-record-sni"]))


if __name__ == "__main__":
    unittest.main()
