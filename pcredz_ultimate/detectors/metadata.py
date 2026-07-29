from __future__ import annotations

import hashlib
import ipaddress
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .base import Detector, safe_decode
from ..inventory import Inventory
from ..models import Finding, NetworkPacket, TCPChunk, UDPDatagram, Endpoint


TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 8883}
GREASE = {0x0A0A + 0x1010 * i for i in range(16)}


class MetadataDetector(Detector):
    name = 'metadata'

    def __init__(self, inventory: Inventory):
        self.inventory = inventory
        self.tls_buffers: dict[tuple[str, str], bytearray] = defaultdict(bytearray)
        self.eapol_seen: set[str] = set()

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        if chunk.flow.service_port in TLS_PORTS or chunk.data[:1] == b'\x16':
            return self._tls(chunk)
        return ()

    def on_udp(self, datagram: UDPDatagram) -> Iterable[Finding]:
        ports = {datagram.src.port, datagram.dst.port}
        if ports & {53, 5353, 5355}:
            self._dns(datagram)
        if ports & {67, 68}:
            self._dhcp(datagram)
        return ()

    def on_l2(self, packet: NetworkPacket) -> Iterable[Finding]:
        if packet.l2_ethertype != 0x888E or len(packet.payload) < 4:
            return ()
        version, packet_type, length = packet.payload[0], packet.payload[1], int.from_bytes(packet.payload[2:4], 'big')
        body = packet.payload[4:4 + length]
        src = Endpoint(packet.src_ip, 0)
        dst = Endpoint(packet.dst_ip, 0)
        if packet_type == 0 and len(body) >= 5:  # EAP packet
            code, identifier, eap_len, eap_type = body[0], body[1], int.from_bytes(body[2:4], 'big'), body[4]
            if code == 2 and eap_type == 1 and eap_len <= len(body):
                identity = safe_decode(body[5:eap_len])
                return [Finding(
                    timestamp=packet.timestamp, protocol='EAPOL', category='identity_exposure',
                    severity='low', title='EAP identity exposed on LAN/WLAN',
                    src=src, dst=dst, username=identity, evidence='EAP-Response/Identity',
                    metadata={'interface': packet.interface_name},
                )]
        if packet_type == 3 and len(body) >= 95:  # EAPOL-Key
            key_info = int.from_bytes(body[1:3], 'big')
            replay = int.from_bytes(body[5:13], 'big')
            nonce = body[13:45].hex()
            mic = body[77:93].hex()
            key = f'{packet.src_mac}>{packet.dst_mac}:{replay}:{mic}'
            if key not in self.eapol_seen:
                self.eapol_seen.add(key)
                return [Finding(
                    timestamp=packet.timestamp, protocol='EAPOL', category='wireless_handshake',
                    severity='info', title='WPA/WPA2 EAPOL-Key handshake material observed',
                    src=src, dst=dst, secret=mic, secret_type='eapol_mic',
                    evidence=f'EAPOL-Key replay_counter={replay}',
                    metadata={'key_info': key_info, 'nonce': nonce, 'mic': mic,
                              'src_mac': packet.src_mac, 'dst_mac': packet.dst_mac,
                              'interface': packet.interface_name},
                )]
        return ()

    def _tls(self, chunk: TCPChunk) -> list[Finding]:
        key = (chunk.flow.flow_id, chunk.direction)
        buf = self.tls_buffers[key]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while len(buf) >= 5:
            content_type = buf[0]
            version = int.from_bytes(buf[1:3], 'big')
            length = int.from_bytes(buf[3:5], 'big')
            if length > 2 * 1024 * 1024 or len(buf) < 5 + length:
                break
            record = bytes(buf[5:5 + length])
            del buf[:5 + length]
            if content_type != 22:
                continue
            pos = 0
            while pos + 4 <= len(record):
                hs_type = record[pos]
                hs_len = int.from_bytes(record[pos + 1:pos + 4], 'big')
                if pos + 4 + hs_len > len(record):
                    break
                body = record[pos + 4:pos + 4 + hs_len]
                pos += 4 + hs_len
                if hs_type == 1 and chunk.direction == 'orig':
                    parsed = self._client_hello(body)
                    if parsed:
                        sni = parsed.get('sni', '')
                        if sni:
                            self.inventory.add_sni(sni)
                        findings.append(Finding(
                            timestamp=chunk.timestamp, protocol='TLS', category='tls_metadata',
                            severity='info', title='TLS ClientHello inventory record',
                            src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                            evidence=f'SNI={sni or "none"} ALPN={",".join(parsed.get("alpn", [])) or "none"}',
                            metadata=parsed,
                        ))
                elif hs_type == 2 and chunk.direction == 'resp':
                    parsed = self._server_hello(body)
                    if parsed:
                        selected = int(parsed.get('selected_version', 0))
                        label = self._tls_version_label(selected)
                        if selected <= 0x0301:
                            severity = 'high'
                            title = f'Legacy {label} negotiated'
                            category = 'weak_transport'
                        elif selected == 0x0302:
                            severity = 'medium'
                            title = 'Legacy TLS 1.1 negotiated'
                            category = 'weak_transport'
                        else:
                            severity = 'info'
                            title = 'TLS ServerHello inventory record'
                            category = 'tls_metadata'
                        findings.append(Finding(
                            timestamp=chunk.timestamp, protocol='TLS', category=category,
                            severity=severity, title=title,
                            src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                            evidence=f'version={label} cipher=0x{parsed.get("cipher_suite", 0):04x}',
                            metadata=parsed,
                        ))
        if len(buf) > 4 * 1024 * 1024:
            del buf[:-5]
        return findings

    @staticmethod
    def _tls_version_label(version: int) -> str:
        return {
            0x0300: 'SSL 3.0',
            0x0301: 'TLS 1.0',
            0x0302: 'TLS 1.1',
            0x0303: 'TLS 1.2',
            0x0304: 'TLS 1.3',
        }.get(version, f'0x{version:04x}')

    @staticmethod
    def _server_hello(body: bytes) -> dict | None:
        if len(body) < 38:
            return None
        legacy_version = int.from_bytes(body[0:2], 'big')
        pos = 34
        sid_len = body[pos]
        pos += 1
        if pos + sid_len + 3 > len(body):
            return None
        session_id = body[pos:pos + sid_len].hex()
        pos += sid_len
        cipher_suite = int.from_bytes(body[pos:pos + 2], 'big')
        pos += 2
        compression = body[pos]
        pos += 1
        selected_version = legacy_version
        extensions: list[int] = []
        alpn = ''
        if pos + 2 <= len(body):
            ext_total = int.from_bytes(body[pos:pos + 2], 'big')
            pos += 2
            end = min(len(body), pos + ext_total)
            while pos + 4 <= end:
                etype = int.from_bytes(body[pos:pos + 2], 'big')
                elen = int.from_bytes(body[pos + 2:pos + 4], 'big')
                pos += 4
                value = body[pos:pos + elen]
                pos += elen
                if len(value) != elen:
                    break
                extensions.append(etype)
                if etype == 43 and len(value) == 2:
                    selected_version = int.from_bytes(value, 'big')
                elif etype == 16 and len(value) >= 3:
                    plen = value[2]
                    if 3 + plen <= len(value):
                        alpn = safe_decode(value[3:3 + plen])
        return {
            'legacy_version': legacy_version,
            'selected_version': selected_version,
            'selected_version_label': MetadataDetector._tls_version_label(selected_version),
            'cipher_suite': cipher_suite,
            'compression_method': compression,
            'extensions': extensions,
            'alpn': alpn,
            'session_id': session_id,
        }

    @staticmethod
    def _client_hello(body: bytes) -> dict | None:
        if len(body) < 34:
            return None
        legacy_version = int.from_bytes(body[0:2], 'big')
        pos = 34
        if pos >= len(body):
            return None
        sid_len = body[pos]
        pos += 1 + sid_len
        if pos + 2 > len(body):
            return None
        cipher_len = int.from_bytes(body[pos:pos + 2], 'big')
        pos += 2
        if pos + cipher_len > len(body):
            return None
        ciphers = [int.from_bytes(body[i:i + 2], 'big') for i in range(pos, pos + cipher_len, 2)]
        pos += cipher_len
        if pos >= len(body):
            return None
        comp_len = body[pos]
        pos += 1 + comp_len
        extensions: list[int] = []
        curves: list[int] = []
        points: list[int] = []
        alpn: list[str] = []
        sni = ''
        supported_versions: list[int] = []
        if pos + 2 <= len(body):
            ext_total = int.from_bytes(body[pos:pos + 2], 'big')
            pos += 2
            end = min(len(body), pos + ext_total)
            while pos + 4 <= end:
                etype = int.from_bytes(body[pos:pos + 2], 'big')
                elen = int.from_bytes(body[pos + 2:pos + 4], 'big')
                pos += 4
                value = body[pos:pos + elen]
                pos += elen
                if len(value) != elen:
                    break
                extensions.append(etype)
                if etype == 0 and len(value) >= 5:
                    name_len = int.from_bytes(value[3:5], 'big')
                    if 5 + name_len <= len(value):
                        sni = safe_decode(value[5:5 + name_len])
                elif etype == 16 and len(value) >= 2:
                    ap = 2
                    while ap < len(value):
                        plen = value[ap]
                        ap += 1
                        alpn.append(safe_decode(value[ap:ap + plen]))
                        ap += plen
                elif etype == 10 and len(value) >= 2:
                    glen = int.from_bytes(value[:2], 'big')
                    curves = [int.from_bytes(value[i:i + 2], 'big') for i in range(2, min(len(value), 2 + glen), 2)]
                elif etype == 11 and value:
                    plen = value[0]
                    points = list(value[1:1 + plen])
                elif etype == 43 and value:
                    vlen = value[0]
                    supported_versions = [int.from_bytes(value[i:i + 2], 'big') for i in range(1, min(len(value), 1 + vlen), 2)]
        ja3_string = ','.join([
            str(legacy_version),
            '-'.join(str(x) for x in ciphers if x not in GREASE),
            '-'.join(str(x) for x in extensions if x not in GREASE),
            '-'.join(str(x) for x in curves if x not in GREASE),
            '-'.join(str(x) for x in points),
        ])
        max_version = max(supported_versions) if supported_versions else legacy_version
        return {
            'legacy_version': legacy_version,
            'supported_versions': supported_versions,
            'max_offered_version': max_version,
            'sni': sni,
            'alpn': alpn,
            'cipher_suites': ciphers,
            'extensions': extensions,
            'ja3': hashlib.md5(ja3_string.encode()).hexdigest(),
            'ja3_string': ja3_string,
        }

    def _dns(self, datagram: UDPDatagram) -> None:
        data = datagram.data
        if len(data) < 12:
            return
        qdcount = int.from_bytes(data[4:6], 'big')
        pos = 12
        for _ in range(min(qdcount, 32)):
            name, pos = self._dns_name(data, pos)
            if not name or pos + 4 > len(data):
                return
            self.inventory.add_dns_query(name)
            pos += 4

    @staticmethod
    def _dns_name(data: bytes, pos: int) -> tuple[str, int]:
        labels: list[str] = []
        original_pos = pos
        jumped = False
        seen = set()
        while pos < len(data):
            if pos in seen:
                return '', original_pos
            seen.add(pos)
            length = data[pos]
            if length == 0:
                pos += 1
                return '.'.join(labels), pos if not jumped else original_pos + 2
            if length & 0xC0 == 0xC0:
                if pos + 1 >= len(data):
                    return '', original_pos
                pointer = ((length & 0x3F) << 8) | data[pos + 1]
                if not jumped:
                    original_pos = pos
                jumped = True
                pos = pointer
                continue
            pos += 1
            if length > 63 or pos + length > len(data):
                return '', original_pos
            labels.append(safe_decode(data[pos:pos + length]))
            pos += length
        return '', original_pos

    def _dhcp(self, datagram: UDPDatagram) -> None:
        data = datagram.data
        if len(data) < 240 or data[236:240] != b'\x63\x82\x53\x63':
            return
        yiaddr = str(ipaddress.IPv4Address(data[16:20]))
        ciaddr = str(ipaddress.IPv4Address(data[12:16]))
        pos = 240
        hostname = ''
        requested_ip = ''
        while pos < len(data):
            code = data[pos]
            pos += 1
            if code == 0:
                continue
            if code == 255:
                break
            if pos >= len(data):
                break
            length = data[pos]
            pos += 1
            value = data[pos:pos + length]
            pos += length
            if code == 12:
                hostname = safe_decode(value)
            elif code == 50 and len(value) == 4:
                requested_ip = str(ipaddress.IPv4Address(value))
            elif code == 81 and len(value) > 3:
                hostname = safe_decode(value[3:])
        ip = requested_ip or (yiaddr if yiaddr != '0.0.0.0' else ciaddr)
        if hostname and ip and ip != '0.0.0.0':
            self.inventory.add_hostname(ip, hostname)
