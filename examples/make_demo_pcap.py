#!/usr/bin/env python3
"""Create a harmless synthetic PCAP containing a segmented HTTP test login."""
from __future__ import annotations
import ipaddress
import struct
from pathlib import Path


def packet(src, dst, sport, dport, seq, flags, payload):
    eth = bytes.fromhex('66778899aabb0011223344550800')
    total = 20 + 20 + len(payload)
    ip = struct.pack('!BBHHHBBH4s4s', 0x45, 0, total, 1, 0, 64, 6, 0,
                     ipaddress.IPv4Address(src).packed, ipaddress.IPv4Address(dst).packed)
    tcp = struct.pack('!HHIIBBHHH', sport, dport, seq, 0, 0x50, flags, 65535, 0, 0)
    return eth + ip + tcp + payload


body = (b'first_name-65467=mpo+popz&last_name-65467=poppers&'
        b'user_email-65467=mpo%40example.test&'
        b'user_password-65467=Disposable-Test-Only!&'
        b'confirm_user_password-65467=Disposable-Test-Only!')
request = (b'POST /register HTTP/1.1\r\nHost: audit.invalid\r\n'
           b'Content-Type: application/x-www-form-urlencoded\r\n' +
           f'Content-Length: {len(body)}\r\n\r\n'.encode() + body)
cut = len(request) // 2
frames = [
    packet('192.0.2.10', '192.0.2.20', 50000, 80, 1000, 0x02, b''),
    packet('192.0.2.10', '192.0.2.20', 50000, 80, 1001, 0x18, request[:cut]),
    packet('192.0.2.10', '192.0.2.20', 50000, 80, 1001 + cut, 0x18, request[cut:]),
]
out = Path(__file__).with_name('demo-segmented-http.pcap')
with out.open('wb') as fh:
    fh.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
    for i, frame in enumerate(frames, start=1):
        fh.write(struct.pack('<IIII', i, 0, len(frame), len(frame)))
        fh.write(frame)
print(out)
