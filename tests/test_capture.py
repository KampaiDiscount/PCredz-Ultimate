from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from pcredz_ultimate.capture import read_capture


class CaptureTests(unittest.TestCase):
    def test_minimal_little_endian_pcapng(self) -> None:
        frame = bytes.fromhex('66778899aabb0011223344550800') + b'payload'
        pad = b'\x00' * ((4 - len(frame) % 4) % 4)
        shb = (
            struct.pack('<II', 0x0A0D0D0A, 28) +
            struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1) +
            struct.pack('<I', 28)
        )
        idb = struct.pack('<IIHHI', 1, 20, 1, 0, 262144) + struct.pack('<I', 20)
        body = struct.pack('<IIIII', 0, 0, 1_000_000, len(frame), len(frame)) + frame + pad
        total = 12 + len(body)
        epb = struct.pack('<II', 6, total) + body + struct.pack('<I', total)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'test.pcapng'
            path.write_bytes(shb + idb + epb)
            packets = list(read_capture(str(path)))
            self.assertEqual(len(packets), 1)
            self.assertEqual(packets[0].data, frame)
            self.assertAlmostEqual(packets[0].timestamp, 1.0)
            self.assertEqual(packets[0].linktype, 1)


if __name__ == '__main__':
    unittest.main()
