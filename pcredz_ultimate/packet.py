from __future__ import annotations

import ipaddress
import struct
from typing import Optional, Tuple

from .models import CapturePacket, NetworkPacket


DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LOOP = 108
DLT_LINUX_SLL = 113
DLT_IEEE802_11_RADIO = 127
DLT_IPV4 = 228
DLT_IPV6 = 229
DLT_LINUX_SLL2 = 276

ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
ETH_P_8021Q = 0x8100
ETH_P_8021AD = 0x88A8
ETH_P_QINQ = 0x9100
ETH_P_EAPOL = 0x888E


def _mac(raw: bytes) -> str:
    return ':'.join(f'{b:02x}' for b in raw)


def _extract_l3(packet: CapturePacket) -> Optional[Tuple[int, bytes, str, str, bytes]]:
    data = packet.data
    linktype = packet.linktype
    src_mac = dst_mac = ''
    raw_l2 = b''

    if linktype == DLT_EN10MB:
        if len(data) < 14:
            return None
        dst_mac = _mac(data[0:6])
        src_mac = _mac(data[6:12])
        ethertype = struct.unpack('!H', data[12:14])[0]
        offset = 14
        while ethertype in {ETH_P_8021Q, ETH_P_8021AD, ETH_P_QINQ}:
            if len(data) < offset + 4:
                return None
            ethertype = struct.unpack('!H', data[offset + 2:offset + 4])[0]
            offset += 4
        raw_l2 = data[offset:]
        return ethertype, data[offset:], src_mac, dst_mac, raw_l2

    if linktype == DLT_LINUX_SLL:
        if len(data) < 16:
            return None
        halen = struct.unpack('!H', data[4:6])[0]
        src_mac = _mac(data[6:6 + min(halen, 8)]) if halen else ''
        proto = struct.unpack('!H', data[14:16])[0]
        raw_l2 = data[16:]
        return proto, data[16:], src_mac, dst_mac, raw_l2

    if linktype == DLT_LINUX_SLL2:
        if len(data) < 20:
            return None
        proto = struct.unpack('!H', data[0:2])[0]
        halen = data[11]
        src_mac = _mac(data[12:12 + min(halen, 8)]) if halen else ''
        raw_l2 = data[20:]
        return proto, data[20:], src_mac, dst_mac, raw_l2

    if linktype in {DLT_RAW, DLT_IPV4, DLT_IPV6}:
        if not data:
            return None
        version = data[0] >> 4
        proto = ETH_P_IP if version == 4 else ETH_P_IPV6 if version == 6 else 0
        return proto, data, src_mac, dst_mac, data

    if linktype in {DLT_NULL, DLT_LOOP}:
        if len(data) < 4:
            return None
        family_le = struct.unpack('<I', data[:4])[0]
        family_be = struct.unpack('>I', data[:4])[0]
        family = family_le if family_le in {2, 24, 28, 30} else family_be
        proto = ETH_P_IP if family == 2 else ETH_P_IPV6
        return proto, data[4:], src_mac, dst_mac, data[4:]

    if linktype == DLT_IEEE802_11_RADIO:
        return _extract_radiotap(data)

    # Last-resort raw IP detection.
    if data and data[0] >> 4 == 4:
        return ETH_P_IP, data, src_mac, dst_mac, data
    if data and data[0] >> 4 == 6:
        return ETH_P_IPV6, data, src_mac, dst_mac, data
    return None


def _extract_radiotap(data: bytes) -> Optional[Tuple[int, bytes, str, str, bytes]]:
    if len(data) < 8:
        return None
    radiotap_len = struct.unpack_from('<H', data, 2)[0]
    if radiotap_len < 8 or radiotap_len + 24 > len(data):
        return None
    frame = data[radiotap_len:]
    fc = struct.unpack_from('<H', frame, 0)[0]
    frame_type = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)
    protected = bool(fc & 0x4000)
    if frame_type != 2 or protected:
        return None

    hdr_len = 24
    if to_ds and from_ds:
        hdr_len += 6
    if subtype & 0x8:
        hdr_len += 2
    if fc & 0x8000:
        hdr_len += 4
    if len(frame) < hdr_len + 8:
        return None

    addr1, addr2, addr3 = frame[4:10], frame[10:16], frame[16:22]
    if not to_ds and not from_ds:
        dst, src = addr1, addr2
    elif to_ds and not from_ds:
        dst, src = addr3, addr2
    elif not to_ds and from_ds:
        dst, src = addr1, addr3
    else:
        addr4 = frame[24:30]
        dst, src = addr3, addr4

    llc = frame[hdr_len:]
    if llc[:6] != b'\xaa\xaa\x03\x00\x00\x00':
        return None
    ethertype = struct.unpack('!H', llc[6:8])[0]
    payload = llc[8:]
    return ethertype, payload, _mac(src), _mac(dst), payload


def parse_packet(packet: CapturePacket) -> Optional[NetworkPacket]:
    extracted = _extract_l3(packet)
    if not extracted:
        return None
    ethertype, l3, src_mac, dst_mac, raw_l2 = extracted

    if ethertype == ETH_P_IP:
        return _parse_ipv4(packet, l3, src_mac, dst_mac, ethertype, raw_l2)
    if ethertype == ETH_P_IPV6:
        return _parse_ipv6(packet, l3, src_mac, dst_mac, ethertype, raw_l2)

    # Keep selected non-IP L2 protocols available to metadata detectors.
    if ethertype == ETH_P_EAPOL:
        return NetworkPacket(
            timestamp=packet.timestamp,
            src_ip=src_mac or 'l2',
            dst_ip=dst_mac or 'l2',
            protocol=0,
            payload=l3,
            src_mac=src_mac,
            dst_mac=dst_mac,
            interface_id=packet.interface_id,
            interface_name=packet.interface_name,
            l2_ethertype=ethertype,
            raw_l2_payload=raw_l2,
        )
    return None


def _parse_ipv4(packet: CapturePacket, data: bytes, src_mac: str, dst_mac: str,
                ethertype: int, raw_l2: bytes) -> Optional[NetworkPacket]:
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack('!H', data[2:4])[0]
    if total_len == 0 or total_len > len(data):
        total_len = len(data)
    flags_frag = struct.unpack('!H', data[6:8])[0]
    frag_offset = flags_frag & 0x1FFF
    more_frags = bool(flags_frag & 0x2000)
    fragmented = frag_offset != 0 or more_frags
    protocol = data[9]
    src_ip = str(ipaddress.IPv4Address(data[12:16]))
    dst_ip = str(ipaddress.IPv4Address(data[16:20]))
    payload = data[ihl:total_len]
    return _parse_transport(packet, src_ip, dst_ip, protocol, payload, src_mac, dst_mac,
                            4, fragmented, ethertype, raw_l2, frag_offset)


def _parse_ipv6(packet: CapturePacket, data: bytes, src_mac: str, dst_mac: str,
                ethertype: int, raw_l2: bytes) -> Optional[NetworkPacket]:
    if len(data) < 40 or data[0] >> 4 != 6:
        return None
    payload_len = struct.unpack('!H', data[4:6])[0]
    next_header = data[6]
    src_ip = str(ipaddress.IPv6Address(data[8:24]))
    dst_ip = str(ipaddress.IPv6Address(data[24:40]))
    end = min(len(data), 40 + payload_len) if payload_len else len(data)
    offset = 40
    fragmented = False
    frag_offset = 0

    # Hop-by-hop, routing, destination options, fragmentation, AH.
    while next_header in {0, 43, 44, 51, 60}:
        if next_header == 44:
            if offset + 8 > end:
                return None
            fragmented = True
            frag_field = struct.unpack('!H', data[offset + 2:offset + 4])[0]
            frag_offset = (frag_field >> 3) & 0x1FFF
            next_header = data[offset]
            offset += 8
            continue
        if offset + 2 > end:
            return None
        current = next_header
        next_header = data[offset]
        if current == 51:
            hdr_len = (data[offset + 1] + 2) * 4
        else:
            hdr_len = (data[offset + 1] + 1) * 8
        offset += hdr_len
        if offset > end:
            return None

    payload = data[offset:end]
    return _parse_transport(packet, src_ip, dst_ip, next_header, payload, src_mac, dst_mac,
                            6, fragmented, ethertype, raw_l2, frag_offset)


def _parse_transport(packet: CapturePacket, src_ip: str, dst_ip: str, protocol: int,
                     payload: bytes, src_mac: str, dst_mac: str, ip_version: int,
                     fragmented: bool, ethertype: int, raw_l2: bytes,
                     frag_offset: int = 0) -> Optional[NetworkPacket]:
    # Non-initial fragments cannot be decoded without IP reassembly.
    if fragmented and frag_offset != 0:
        return NetworkPacket(
            packet.timestamp, src_ip, dst_ip, protocol, b'', src_mac=src_mac,
            dst_mac=dst_mac, interface_id=packet.interface_id,
            interface_name=packet.interface_name, ip_version=ip_version,
            fragmented=True, l2_ethertype=ethertype, raw_l2_payload=raw_l2,
        )

    if protocol == 6:
        if len(payload) < 20:
            return None
        src_port, dst_port, seq, ack = struct.unpack('!HHII', payload[:12])
        data_offset = (payload[12] >> 4) * 4
        if data_offset < 20 or len(payload) < data_offset:
            return None
        flags = payload[13]
        app = payload[data_offset:]
        return NetworkPacket(
            packet.timestamp, src_ip, dst_ip, protocol, app, src_port, dst_port,
            seq, ack, flags, src_mac, dst_mac, packet.interface_id,
            packet.interface_name, ip_version, fragmented, ethertype, raw_l2,
        )

    if protocol == 17:
        if len(payload) < 8:
            return None
        src_port, dst_port, length = struct.unpack('!HHH', payload[:6])
        end = min(len(payload), length) if length >= 8 else len(payload)
        app = payload[8:end]
        return NetworkPacket(
            packet.timestamp, src_ip, dst_ip, protocol, app, src_port, dst_port,
            src_mac=src_mac, dst_mac=dst_mac, interface_id=packet.interface_id,
            interface_name=packet.interface_name, ip_version=ip_version,
            fragmented=fragmented, l2_ethertype=ethertype, raw_l2_payload=raw_l2,
        )

    return NetworkPacket(
        packet.timestamp, src_ip, dst_ip, protocol, payload, src_mac=src_mac,
        dst_mac=dst_mac, interface_id=packet.interface_id,
        interface_name=packet.interface_name, ip_version=ip_version,
        fragmented=fragmented, l2_ethertype=ethertype, raw_l2_payload=raw_l2,
    )
