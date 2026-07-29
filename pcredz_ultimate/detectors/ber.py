from __future__ import annotations

from dataclasses import dataclass


@dataclass
class TLV:
    tag: int
    value: bytes
    start: int
    end: int


def read_tlv(data: bytes, offset: int = 0) -> TLV | None:
    if offset + 2 > len(data):
        return None
    tag = data[offset]
    first_len = data[offset + 1]
    pos = offset + 2
    if first_len & 0x80:
        count = first_len & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            return None
        length = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    else:
        length = first_len
    end = pos + length
    if end > len(data):
        return None
    return TLV(tag, data[pos:end], offset, end)


def integer_value(tlv: TLV) -> int:
    return int.from_bytes(tlv.value, 'big', signed=False) if tlv.value else 0
