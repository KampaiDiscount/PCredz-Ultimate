from __future__ import annotations

import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .base import Detector, parse_sasl_plain, printable_ratio, safe_decode
from ..models import Finding, TCPChunk, UDPDatagram


@dataclass
class SocksState:
    buffer: bytearray = field(default_factory=bytearray)
    auth_selected: bool = False
    completed: bool = False


class MessagingDetector(Detector):
    name = 'messaging'

    def __init__(self):
        self.mqtt_buffers: dict[str, bytearray] = defaultdict(bytearray)
        self.socks: dict[str, SocksState] = defaultdict(SocksState)
        self.amqp_buffers: dict[str, bytearray] = defaultdict(bytearray)
        self.memcached_buffers: dict[str, bytearray] = defaultdict(bytearray)

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        if chunk.flow.service_port == 1883 and chunk.direction == 'orig':
            return self._mqtt(chunk)
        if chunk.flow.service_port == 1080:
            return self._socks5(chunk)
        if chunk.flow.service_port == 5672 and chunk.direction == 'orig':
            return self._amqp_091(chunk)
        if chunk.flow.service_port == 11211 and chunk.direction == 'orig':
            return self._memcached_sasl(chunk)
        return ()

    def on_udp(self, datagram: UDPDatagram) -> Iterable[Finding]:
        if datagram.src.port in {1812, 1813, 1645, 1646} or datagram.dst.port in {1812, 1813, 1645, 1646}:
            return self._radius(datagram)
        return ()

    def _mqtt(self, chunk: TCPChunk) -> list[Finding]:
        buf = self.mqtt_buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while len(buf) >= 2:
            packet_type = buf[0] >> 4
            remaining, used = self._decode_varint(buf, 1)
            if remaining is None:
                break
            total = 1 + used + remaining
            if len(buf) < total:
                break
            packet = bytes(buf[:total])
            del buf[:total]
            if packet_type == 1:
                finding = self._parse_mqtt_connect(chunk, packet, 1 + used)
                if finding:
                    findings.append(finding)
        if len(buf) > 4 * 1024 * 1024:
            del buf[:-1024]
        return findings

    @staticmethod
    def _decode_varint(data: bytes | bytearray, pos: int) -> tuple[int | None, int]:
        multiplier = 1
        value = 0
        used = 0
        while pos + used < len(data) and used < 4:
            encoded = data[pos + used]
            value += (encoded & 127) * multiplier
            used += 1
            if not (encoded & 128):
                return value, used
            multiplier *= 128
        return None, used

    @staticmethod
    def _read_mqtt_field(data: bytes, pos: int) -> tuple[bytes | None, int]:
        if pos + 2 > len(data):
            return None, pos
        length = int.from_bytes(data[pos:pos + 2], 'big')
        pos += 2
        if pos + length > len(data):
            return None, pos
        return data[pos:pos + length], pos + length

    def _parse_mqtt_connect(self, chunk: TCPChunk, packet: bytes, pos: int) -> Finding | None:
        proto_raw, pos = self._read_mqtt_field(packet, pos)
        if proto_raw is None or pos + 4 > len(packet):
            return None
        protocol_name = safe_decode(proto_raw)
        level = packet[pos]
        flags = packet[pos + 1]
        pos += 4  # level, flags, keepalive
        if level == 5:
            prop_len, used = self._decode_varint(packet, pos)
            if prop_len is None:
                return None
            pos += used + prop_len
        client_id_raw, pos = self._read_mqtt_field(packet, pos)
        if client_id_raw is None:
            return None
        client_id = safe_decode(client_id_raw)
        will_flag = bool(flags & 0x04)
        if will_flag:
            if level == 5:
                prop_len, used = self._decode_varint(packet, pos)
                if prop_len is None:
                    return None
                pos += used + prop_len
            _, pos = self._read_mqtt_field(packet, pos)  # will topic
            _, pos = self._read_mqtt_field(packet, pos)  # will payload
        username = ''
        password = b''
        if flags & 0x80:
            raw, pos = self._read_mqtt_field(packet, pos)
            if raw is None:
                return None
            username = safe_decode(raw)
        if flags & 0x40:
            raw, pos = self._read_mqtt_field(packet, pos)
            if raw is None:
                return None
            password = raw
        if not password:
            return None
        secret = safe_decode(password) if printable_ratio(password) >= 0.8 else password.hex()
        secret_type = 'password' if printable_ratio(password) >= 0.8 else 'binary_auth_data'
        return Finding(
            timestamp=chunk.timestamp, protocol='MQTT', category='cleartext_credential',
            severity='high', title='MQTT CONNECT credential exposed',
            src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
            username=username, secret=secret, secret_type=secret_type,
            evidence=f'MQTT {protocol_name} level {level} CONNECT client_id={client_id}',
            metadata={'protocol_name': protocol_name, 'level': level, 'client_id': client_id},
        )

    def _socks5(self, chunk: TCPChunk) -> list[Finding]:
        state = self.socks[chunk.flow.flow_id]
        if state.completed:
            return []
        if chunk.direction == 'resp':
            if len(chunk.data) >= 2 and chunk.data[0] == 0x05 and chunk.data[1] == 0x02:
                state.auth_selected = True
            return []
        state.buffer.extend(chunk.data)
        if len(state.buffer) > 4096:
            state.completed = True
            return []
        data = bytes(state.buffer)
        # Skip initial method negotiation if present.
        pos = 0
        if len(data) >= 2 and data[0] == 0x05:
            nmethods = data[1]
            if len(data) < 2 + nmethods:
                return []
            if 0x02 in data[2:2 + nmethods]:
                pos = 2 + nmethods
            else:
                return []
        if len(data) < pos + 3 or data[pos] != 0x01:
            return []
        ulen = data[pos + 1]
        if len(data) < pos + 2 + ulen + 1:
            return []
        username = safe_decode(data[pos + 2:pos + 2 + ulen])
        ppos = pos + 2 + ulen
        plen = data[ppos]
        if len(data) < ppos + 1 + plen:
            return []
        password = safe_decode(data[ppos + 1:ppos + 1 + plen])
        state.completed = True
        return [Finding(
            timestamp=chunk.timestamp, protocol='SOCKS5', category='cleartext_credential',
            severity='high', title='SOCKS5 username/password exposed',
            src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
            username=username, secret=password, secret_type='password',
            evidence='RFC 1929 username/password subnegotiation',
        )]


    def _amqp_091(self, chunk: TCPChunk) -> list[Finding]:
        """Parse AMQP 0-9-1 Connection.Start-Ok SASL responses."""
        buf = self.amqp_buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        # The client protocol header is not an AMQP frame.
        while len(buf) >= 8 and bytes(buf[:4]) == b'AMQP':
            del buf[:8]
        while len(buf) >= 8:
            frame_type = buf[0]
            size = int.from_bytes(buf[3:7], 'big')
            total = 7 + size + 1
            if size > 16 * 1024 * 1024:
                del buf[:1]
                continue
            if len(buf) < total:
                break
            payload = bytes(buf[7:7 + size])
            frame_end = buf[7 + size]
            del buf[:total]
            if frame_end != 0xCE or frame_type != 1 or len(payload) < 4:
                continue
            class_id = int.from_bytes(payload[:2], 'big')
            method_id = int.from_bytes(payload[2:4], 'big')
            if (class_id, method_id) != (10, 11):  # Connection.Start-Ok
                continue
            pos = 4
            if pos + 4 > len(payload):
                continue
            table_len = int.from_bytes(payload[pos:pos + 4], 'big')
            pos += 4 + table_len
            if pos >= len(payload):
                continue
            mlen = payload[pos]
            pos += 1
            if pos + mlen + 4 > len(payload):
                continue
            mechanism = safe_decode(payload[pos:pos + mlen]).upper()
            pos += mlen
            rlen = int.from_bytes(payload[pos:pos + 4], 'big')
            pos += 4
            if pos + rlen > len(payload):
                continue
            response = payload[pos:pos + rlen]
            if mechanism == 'PLAIN':
                parsed = parse_sasl_plain(response)
                if parsed:
                    authzid, username, password = parsed
                    findings.append(Finding(
                        timestamp=chunk.timestamp, protocol='AMQP', category='cleartext_credential',
                        severity='high', title='AMQP SASL PLAIN credential exposed',
                        src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                        username=username, secret=password, secret_type='password',
                        evidence='AMQP 0-9-1 Connection.Start-Ok mechanism=PLAIN',
                        metadata={'mechanism': mechanism, 'authzid': authzid},
                    ))
            elif response:
                findings.append(Finding(
                    timestamp=chunk.timestamp, protocol='AMQP', category='authentication_exchange',
                    severity='low', title=f'AMQP SASL {mechanism or "unknown"} response observed',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    secret=response.hex(), secret_type='sasl_response',
                    evidence='AMQP 0-9-1 Connection.Start-Ok',
                    metadata={'mechanism': mechanism, 'response': response.hex()},
                ))
        if len(buf) > 4 * 1024 * 1024:
            del buf[:-1024]
        return findings

    def _memcached_sasl(self, chunk: TCPChunk) -> list[Finding]:
        """Parse Memcached binary-protocol SASL AUTH/STEP requests."""
        buf = self.memcached_buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while len(buf) >= 24:
            if buf[0] != 0x80:  # Binary request magic.
                del buf[:1]
                continue
            opcode = buf[1]
            key_len = int.from_bytes(buf[2:4], 'big')
            extras_len = buf[4]
            body_len = int.from_bytes(buf[8:12], 'big')
            total = 24 + body_len
            if body_len > 16 * 1024 * 1024:
                del buf[:1]
                continue
            if len(buf) < total:
                break
            body = bytes(buf[24:total])
            del buf[:total]
            if opcode not in {0x21, 0x22} or extras_len + key_len > len(body):
                continue
            mechanism = safe_decode(body[extras_len:extras_len + key_len]).upper()
            response = body[extras_len + key_len:]
            if mechanism == 'PLAIN':
                parsed = parse_sasl_plain(response)
                if not parsed:
                    continue
                authzid, username, password = parsed
                findings.append(Finding(
                    timestamp=chunk.timestamp, protocol='Memcached', category='cleartext_credential',
                    severity='high', title='Memcached SASL PLAIN credential exposed',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    username=username, secret=password, secret_type='password',
                    evidence='Memcached binary SASL_AUTH mechanism=PLAIN',
                    metadata={'mechanism': mechanism, 'authzid': authzid, 'opcode': opcode},
                ))
            elif response:
                findings.append(Finding(
                    timestamp=chunk.timestamp, protocol='Memcached', category='authentication_exchange',
                    severity='low', title=f'Memcached SASL {mechanism or "unknown"} response observed',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    secret=response.hex(), secret_type='sasl_response',
                    evidence='Memcached binary SASL authentication',
                    metadata={'mechanism': mechanism, 'response': response.hex(), 'opcode': opcode},
                ))
        if len(buf) > 4 * 1024 * 1024:
            del buf[:-1024]
        return findings

    def _radius(self, datagram: UDPDatagram) -> list[Finding]:
        data = datagram.data
        if len(data) < 20:
            return []
        code, identifier, length = data[0], data[1], int.from_bytes(data[2:4], 'big')
        if length < 20 or length > len(data):
            return []
        authenticator = data[4:20]
        pos = 20
        attrs: dict[int, list[bytes]] = defaultdict(list)
        while pos + 2 <= length:
            atype, alen = data[pos], data[pos + 1]
            if alen < 2 or pos + alen > length:
                break
            attrs[atype].append(data[pos + 2:pos + alen])
            pos += alen
        username = safe_decode(attrs.get(1, [b''])[0]) if attrs.get(1) else ''
        findings: list[Finding] = []
        if attrs.get(2):
            ciphertext = attrs[2][0].hex()
            findings.append(Finding(
                timestamp=datagram.timestamp, protocol='RADIUS', category='protected_credential',
                severity='medium', title='RADIUS PAP password ciphertext captured',
                src=datagram.src, dst=datagram.dst, username=username,
                secret=ciphertext, secret_type='radius_user_password_ciphertext',
                evidence=f'RADIUS code={code} id={identifier}',
                metadata={'request_authenticator': authenticator.hex(), 'attribute': 'User-Password'},
            ))
        if attrs.get(3):
            value = attrs[3][0]
            chap_id = value[0] if value else 0
            response = value[1:].hex() if len(value) > 1 else ''
            challenge = attrs.get(60, [authenticator])[0].hex()
            findings.append(Finding(
                timestamp=datagram.timestamp, protocol='RADIUS', category='challenge_response',
                severity='medium', title='RADIUS CHAP response captured',
                src=datagram.src, dst=datagram.dst, username=username,
                secret=response, secret_type='chap_response',
                evidence=f'RADIUS CHAP id={chap_id}',
                metadata={'challenge': challenge, 'chap_id': chap_id,
                          'hashcat': f'{username}:{chap_id:02x}:{challenge}:{response}',
                          'hash_file': 'RADIUS-CHAP.txt'},
            ))
        for eap in attrs.get(79, []):
            if len(eap) >= 5:
                eap_code = eap[0]
                eap_type = eap[4]
                if eap_code == 2 and eap_type == 1:
                    identity = safe_decode(eap[5:])
                    findings.append(Finding(
                        timestamp=datagram.timestamp, protocol='EAP', category='identity_exposure',
                        severity='low', title='EAP identity exposed in RADIUS',
                        src=datagram.src, dst=datagram.dst, username=identity,
                        evidence='EAP-Response/Identity attribute',
                    ))
        return findings
