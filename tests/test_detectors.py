from __future__ import annotations

import base64
import unittest

from pcredz_ultimate.detectors.line_auth import LineAuthDetector
from pcredz_ultimate.detectors.base import extract_structured_credentials, infer_structured_identity
from pcredz_ultimate.detectors.directory import DirectoryDetector
from pcredz_ultimate.detectors.databases import DatabaseDetector
from pcredz_ultimate.detectors.messaging import MessagingDetector
from pcredz_ultimate.detectors.metadata import MetadataDetector
from pcredz_ultimate.detectors.http import HTTPDetector
from pcredz_ultimate.inventory import Inventory
from pcredz_ultimate.models import Endpoint, FlowContext, TCPChunk, UDPDatagram


def chunk(port: int, data: bytes, direction: str = 'orig') -> TCPChunk:
    client = Endpoint('10.0.0.2', 50000)
    server = Endpoint('10.0.0.1', port)
    flow = FlowContext('testflow', client, server, port, first_seen=1.0, last_seen=1.0)
    src, dst = (client, server) if direction == 'orig' else (server, client)
    return TCPChunk(1.0, flow, direction, src, dst, data)


class DetectorTests(unittest.TestCase):

    def test_structured_identity_combines_first_and_last_name_before_email(self) -> None:
        items = [
            ("first_name-65467", "Alex"),
            ("last_name-65467", "Example"),
            ("user_email-65467", "alex@example.test"),
            ("user_password-65467", "P@ssw0rd123"),
            ("confirm_user_password-65467", "P@ssw0rd123"),
        ]
        self.assertEqual(infer_structured_identity(items), "Alex Example")
        findings = extract_structured_credentials(items)
        self.assertEqual(findings, [("user_password-65467", "Alex Example", "P@ssw0rd123")])

    def test_structured_identity_explicit_username_beats_human_name(self) -> None:
        items = [
            ("first_name", "Alice"),
            ("last_name", "Example"),
            ("email", "alice@example.test"),
            ("login_name", "alice-admin"),
            ("password", "DisposableOnly!"),
        ]
        self.assertEqual(infer_structured_identity(items), "alice-admin")

    def test_smtp_auth_plain(self) -> None:
        detector = LineAuthDetector()
        token = base64.b64encode(b'\x00alice\x00mailpass')
        findings = list(detector.on_tcp(chunk(25, b'AUTH PLAIN ' + token + b'\r\n')))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, 'alice')
        self.assertEqual(findings[0].secret, 'mailpass')

    def test_socks5_username_password(self) -> None:
        detector = MessagingDetector()
        findings = []
        findings.extend(detector.on_tcp(chunk(1080, b'\x05\x01\x02')))
        findings.extend(detector.on_tcp(chunk(1080, b'\x01\x05alice\x06secret')))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, 'alice')
        self.assertEqual(findings[0].secret, 'secret')

    def test_amqp_sasl_plain(self) -> None:
        detector = MessagingDetector()
        response = b"\x00rabbit\x00carrot"
        payload = (b"\x00\x0a\x00\x0b" + b"\x00\x00\x00\x00" +
                   b"\x05PLAIN" + len(response).to_bytes(4, "big") + response + b"\x05en_US")
        frame = b"\x01\x00\x00" + len(payload).to_bytes(4, "big") + payload + b"\xce"
        findings = list(detector.on_tcp(chunk(5672, b"AMQP\x00\x00\x09\x01" + frame)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, "rabbit")
        self.assertEqual(findings[0].secret, "carrot")

    def test_memcached_sasl_plain(self) -> None:
        detector = MessagingDetector()
        key = b"PLAIN"
        response = b"\x00cacheuser\x00cachepass"
        body = key + response
        header = (b"\x80\x21" + len(key).to_bytes(2, "big") + b"\x00\x00\x00\x00" +
                  len(body).to_bytes(4, "big") + b"\x00" * 12)
        findings = list(detector.on_tcp(chunk(11211, header + body)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, "cacheuser")
        self.assertEqual(findings[0].secret, "cachepass")


    def test_structured_short_pass_and_otp_fields(self) -> None:
        items = [
            ("username", "alice"),
            ("pass", "shortpass"),
            ("mfa_code", "123456"),
        ]
        findings = extract_structured_credentials(items)
        self.assertEqual(findings, [
            ("pass", "alice", "shortpass"),
            ("mfa_code", "alice", "123456"),
        ])

    def test_http_multiple_set_cookie_headers(self) -> None:
        detector = HTTPDetector(Inventory())
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Length: 0\r\n"
            b"Set-Cookie: PHPSESSID=alpha; Path=/\r\n"
            b"Set-Cookie: auth_token=bravo; Path=/; HttpOnly\r\n\r\n"
        )
        findings = list(detector.on_tcp(chunk(80, response, direction="resp")))
        self.assertEqual({f.secret for f in findings}, {"alpha", "bravo"})

    def test_tls13_server_hello_selected_version(self) -> None:
        body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00" +
                b"\x00\x06" + b"\x00\x2b\x00\x02\x03\x04")
        parsed = MetadataDetector._server_hello(body)
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["selected_version"], 0x0304)
        self.assertEqual(parsed["selected_version_label"], "TLS 1.3")

    def test_ldap_simple_bind(self) -> None:
        detector = DirectoryDetector()
        bind = b"\x02\x01\x03" + b"\x04\x08cn=alice" + b"\x80\x06ldappw"
        message = b"\x02\x01\x01" + b"\x60" + bytes([len(bind)]) + bind
        packet = b"\x30" + bytes([len(message)]) + message
        findings = list(detector.on_tcp(chunk(389, packet)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, "cn=alice")
        self.assertEqual(findings[0].secret, "ldappw")

    def test_snmp_v2c_community(self) -> None:
        detector = DirectoryDetector()
        body = b"\x02\x01\x01" + b"\x04\x06public"
        message = b"\x30" + bytes([len(body)]) + body
        datagram = UDPDatagram(1.0, Endpoint("10.0.0.2", 50000), Endpoint("10.0.0.1", 161),
                               message, "10.0.0.2", "10.0.0.1")
        findings = list(detector.on_udp(datagram))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].secret, "public")

    def test_mqtt_connect_credential(self) -> None:
        detector = MessagingDetector()
        def field(value: bytes) -> bytes:
            return len(value).to_bytes(2, "big") + value
        variable_and_payload = (field(b"MQTT") + b"\x04\xc2\x00\x3c" +
                                field(b"sensor-1") + field(b"iotuser") + field(b"iotpass"))
        packet = b"\x10" + bytes([len(variable_and_payload)]) + variable_and_payload
        findings = list(detector.on_tcp(chunk(1883, packet)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, "iotuser")
        self.assertEqual(findings[0].secret, "iotpass")

    def test_redis_resp_auth(self) -> None:
        detector = DatabaseDetector()
        command = b"*3\r\n$4\r\nAUTH\r\n$5\r\nalice\r\n$7\r\nredisPW\r\n"
        findings = list(detector.on_tcp(chunk(6379, command)))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].username, "alice")
        self.assertEqual(findings[0].secret, "redisPW")

    def test_mssql_password_deobfuscation(self) -> None:
        plain = "SqlP@ss!".encode("utf-16le")
        raw = bytes(((((b & 0x0f) << 4) | ((b & 0xf0) >> 4)) ^ 0xa5) for b in plain)
        self.assertEqual(DatabaseDetector._deobfuscate_tds_password(raw), "SqlP@ss!")


if __name__ == '__main__':
    unittest.main()
