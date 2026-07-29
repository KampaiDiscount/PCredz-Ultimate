from __future__ import annotations

import ipaddress
import json
import hashlib
import struct
import tempfile
import unittest
from pathlib import Path

from pcredz_ultimate.engine import AuditEngine


def ethernet_ipv4_tcp(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                      seq: int, ack: int, flags: int, payload: bytes,
                      src_mac: bytes = b'\x00\x11\x22\x33\x44\x55',
                      dst_mac: bytes = b'\x66\x77\x88\x99\xaa\xbb') -> bytes:
    eth = dst_mac + src_mac + struct.pack('!H', 0x0800)
    total_len = 20 + 20 + len(payload)
    ip = struct.pack(
        '!BBHHHBBH4s4s',
        0x45, 0, total_len, 1, 0, 64, 6, 0,
        ipaddress.IPv4Address(src_ip).packed,
        ipaddress.IPv4Address(dst_ip).packed,
    )
    tcp = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack, 5 << 4, flags, 65535, 0, 0)
    return eth + ip + tcp + payload


def write_pcap(path: Path, packets: list[tuple[float, bytes]]) -> None:
    with path.open('wb') as fh:
        fh.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for ts, data in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            fh.write(struct.pack('<IIII', sec, usec, len(data), len(data)))
            fh.write(data)


class EndToEndTests(unittest.TestCase):
    def test_segmented_dynamic_http_form_and_noise_suppression(self) -> None:
        request_body = (
            b'first_name-65467=Alex&last_name-65467=Example&user_email-65467=test%40example.test&'
            b'user_password-65467=P%40ssw0rd123&'
            b'confirm_user_password-65467=P%40ssw0rd123'
        )
        request = (
            b'POST /register/ HTTP/1.1\r\n'
            b'Host: shop.example.test\r\n'
            b'Content-Type: application/x-www-form-urlencoded\r\n'
            + f'Content-Length: {len(request_body)}\r\n'.encode()
            + b'\r\n' + request_body
        )
        split = request.find(b'user_password') + 8
        p1, p2 = request[:split], request[split:]
        packets = [
            (1.0, ethernet_ipv4_tcp('192.0.2.10', '198.51.100.20', 53219, 80, 1000, 0, 0x02, b'')),
            (1.1, ethernet_ipv4_tcp('192.0.2.10', '198.51.100.20', 53219, 80, 1001, 0, 0x18, p1)),
            (1.2, ethernet_ipv4_tcp('198.51.100.20', '192.0.2.10', 80, 53219, 9000, 1001 + len(p1), 0x18,
                                    b'HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 12\r\n\r\n\x00\xffpassword=')),
            (1.3, ethernet_ipv4_tcp('192.0.2.10', '198.51.100.20', 53219, 80, 1001 + len(p1), 0, 0x18, p2)),
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capture = root / 'test.pcap'
            output = root / 'audit'
            write_pcap(capture, packets)
            engine = AuditEngine(str(output))
            engine.process_capture(str(capture))
            engine.finalize()

            rows = [json.loads(line) for line in (output / 'findings.jsonl').read_text().splitlines()]
            credential_rows = [row for row in rows if row['category'] == 'cleartext_credential']
            self.assertEqual(len(credential_rows), 1)
            finding = credential_rows[0]
            self.assertEqual(finding['username'], 'Alex Example')
            self.assertEqual(finding['secret_type'], 'user_password-65467')
            self.assertNotIn('P@ssw0rd123', (output / 'findings.jsonl').read_text())
            self.assertNotIn('P@ssw0rd123', (output / 'findings.csv').read_text())
            self.assertNotIn('P@ssw0rd123', (output / 'report.html').read_text())
            self.assertEqual(finding['secret_fingerprint'],
                             hashlib.sha256(b'P@ssw0rd123').hexdigest())

    def test_reveal_secrets_is_explicit(self) -> None:
        body = b'username=alice&password=CorrectHorseBatteryStaple'
        request = (b'POST /login HTTP/1.1\r\nHost: audit.test\r\n'
                   b'Content-Type: application/x-www-form-urlencoded\r\n' +
                   f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
        packets = [
            (1.0, ethernet_ipv4_tcp('10.0.0.2', '10.0.0.1', 40000, 80, 1, 0, 0x18, request)),
        ]
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            capture = root / 'test.pcap'
            output = root / 'audit'
            write_pcap(capture, packets)
            engine = AuditEngine(str(output), reveal_secrets=True)
            engine.process_capture(str(capture))
            engine.finalize()
            self.assertIn('CorrectHorseBatteryStaple', (output / 'findings.jsonl').read_text())


if __name__ == '__main__':
    unittest.main()
