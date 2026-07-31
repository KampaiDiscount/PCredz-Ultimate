from __future__ import annotations

import io
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator, Optional

from .models import CapturePacket


PCAP_MAGICS = {
    b'\xd4\xc3\xb2\xa1': ('<', 1_000_000.0),
    b'\xa1\xb2\xc3\xd4': ('>', 1_000_000.0),
    b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000.0),
    b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000.0),
}
PCAPNG_MAGIC = b'\x0a\x0d\x0d\x0a'


@dataclass
class InterfaceInfo:
    linktype: int
    snaplen: int
    ts_resolution: float = 1_000_000.0
    ts_offset: float = 0.0
    name: str = ''


def _decode_options(data: bytes, endian: str) -> dict[int, list[bytes]]:
    options: dict[int, list[bytes]] = {}
    pos = 0
    while pos + 4 <= len(data):
        code, length = struct.unpack_from(endian + 'HH', data, pos)
        pos += 4
        if code == 0:
            break
        value = data[pos:pos + length]
        options.setdefault(code, []).append(value)
        pos += (length + 3) & ~3
    return options


def _ts_resolution_from_option(raw: bytes) -> float:
    if not raw:
        return 1_000_000.0
    value = raw[0]
    if value & 0x80:
        return float(2 ** (value & 0x7F))
    return float(10 ** value)


def read_capture(path: str) -> Iterator[CapturePacket]:
    with open(path, 'rb') as fh:
        magic = fh.read(4)
        fh.seek(0)
        if magic in PCAP_MAGICS:
            yield from _read_pcap(fh)
        elif magic == PCAPNG_MAGIC:
            yield from _read_pcapng(fh)
        else:
            raise ValueError(f'Unsupported capture format or corrupt file: {path}')


def _read_pcap(fh: BinaryIO) -> Iterator[CapturePacket]:
    header = fh.read(24)
    if len(header) != 24:
        raise ValueError('Truncated PCAP global header')
    magic = header[:4]
    endian, resolution = PCAP_MAGICS[magic]
    _, _, _, _, _, linktype = struct.unpack(endian + 'HHIIII', header[4:])

    while True:
        ph = fh.read(16)
        if not ph:
            break
        if len(ph) != 16:
            raise ValueError('Truncated PCAP packet header')
        ts_sec, ts_frac, incl_len, orig_len = struct.unpack(endian + 'IIII', ph)
        data = fh.read(incl_len)
        if len(data) != incl_len:
            raise ValueError('Truncated PCAP packet data')
        yield CapturePacket(
            timestamp=ts_sec + ts_frac / resolution,
            data=data,
            linktype=linktype,
            original_length=orig_len,
        )


def _read_pcapng(fh: BinaryIO) -> Iterator[CapturePacket]:
    endian = '<'
    interfaces: list[InterfaceInfo] = []

    while True:
        block_header = fh.read(8)
        if not block_header:
            break
        if len(block_header) != 8:
            raise ValueError('Truncated PCAPNG block header')

        raw_type = block_header[:4]
        if raw_type == PCAPNG_MAGIC:
            # Need the byte-order magic before we can interpret block length.
            body_prefix = fh.read(4)
            if len(body_prefix) != 4:
                raise ValueError('Truncated PCAPNG section header')
            if body_prefix == b'\x4d\x3c\x2b\x1a':
                endian = '<'
            elif body_prefix == b'\x1a\x2b\x3c\x4d':
                endian = '>'
            else:
                raise ValueError('Invalid PCAPNG byte-order magic')
            total_len = struct.unpack(endian + 'I', block_header[4:])[0]
            if total_len < 28:
                raise ValueError('Invalid PCAPNG section length')
            remainder = fh.read(total_len - 12)
            if len(remainder) != total_len - 12:
                raise ValueError('Truncated PCAPNG section')
            interfaces = []
            continue

        block_type, total_len = struct.unpack(endian + 'II', block_header)
        if total_len < 12 or total_len % 4:
            raise ValueError(f'Invalid PCAPNG block length: {total_len}')
        body = fh.read(total_len - 12)
        trailer = fh.read(4)
        if len(body) != total_len - 12 or len(trailer) != 4:
            raise ValueError('Truncated PCAPNG block')
        if struct.unpack(endian + 'I', trailer)[0] != total_len:
            raise ValueError('PCAPNG block length mismatch')

        if block_type == 1:  # Interface Description Block
            if len(body) < 8:
                continue
            linktype, _, snaplen = struct.unpack_from(endian + 'HHI', body, 0)
            opts = _decode_options(body[8:], endian)
            name = ''
            if 2 in opts and opts[2]:
                name = opts[2][0].decode('utf-8', errors='replace').rstrip('\x00')
            ts_resolution = 1_000_000.0
            if 9 in opts and opts[9]:
                ts_resolution = _ts_resolution_from_option(opts[9][0])
            ts_offset = 0.0
            if 14 in opts and opts[14] and len(opts[14][0]) >= 8:
                ts_offset = float(struct.unpack(endian + 'q', opts[14][0][:8])[0])
            interfaces.append(InterfaceInfo(linktype, snaplen, ts_resolution, ts_offset, name))

        elif block_type == 6:  # Enhanced Packet Block
            if len(body) < 20:
                continue
            iface_id, ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + 'IIIII', body, 0)
            if iface_id >= len(interfaces):
                continue
            packet_data = body[20:20 + cap_len]
            iface = interfaces[iface_id]
            ts_raw = (ts_hi << 32) | ts_lo
            timestamp = iface.ts_offset + ts_raw / iface.ts_resolution
            yield CapturePacket(
                timestamp=timestamp,
                data=packet_data,
                linktype=iface.linktype,
                interface_id=iface_id,
                interface_name=iface.name,
                original_length=orig_len,
            )

        elif block_type == 3:  # Simple Packet Block
            if not interfaces or len(body) < 4:
                continue
            orig_len = struct.unpack_from(endian + 'I', body, 0)[0]
            packet_data = body[4:min(len(body), 4 + orig_len)]
            iface = interfaces[0]
            yield CapturePacket(
                timestamp=0.0,
                data=packet_data,
                linktype=iface.linktype,
                interface_id=0,
                interface_name=iface.name,
                original_length=orig_len,
            )

        elif block_type == 2:  # Obsolete Packet Block
            if len(body) < 20:
                continue
            iface_id = struct.unpack_from(endian + 'H', body, 0)[0]
            if iface_id >= len(interfaces):
                continue
            ts_hi, ts_lo, cap_len, orig_len = struct.unpack_from(endian + 'IIII', body, 4)
            packet_data = body[20:20 + cap_len]
            iface = interfaces[iface_id]
            ts_raw = (ts_hi << 32) | ts_lo
            timestamp = iface.ts_offset + ts_raw / iface.ts_resolution
            yield CapturePacket(timestamp, packet_data, iface.linktype, iface_id, iface.name, orig_len)


def live_capture(interface: str, snaplen: int = 262144, promisc: bool = True, timeout_ms: int = 100) -> Iterator[CapturePacket]:
    try:
        import pcapy  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            'Live capture backend unavailable. Run ./install.sh --live; on Kali/Debian/Ubuntu '
            'this installs the compiler, Python headers, libpcap development headers, and pcapy-ng.'
        ) from exc

    reader = pcapy.open_live(interface, snaplen, promisc, timeout_ms)
    linktype = reader.datalink()
    while True:
        header, data = reader.next()
        if not header:
            continue
        sec, usec = header.getts()
        yield CapturePacket(sec + usec / 1_000_000.0, data, linktype, 0, interface, len(data))
