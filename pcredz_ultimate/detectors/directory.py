from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .base import Detector, safe_decode
from .ber import read_tlv, integer_value
from ..models import Finding, TCPChunk, UDPDatagram


class DirectoryDetector(Detector):
    name = 'directory'

    def __init__(self, max_buffer: int = 1024 * 1024):
        self.buffers: dict[str, bytearray] = defaultdict(bytearray)
        self.max_buffer = max_buffer

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        if chunk.flow.service_port != 389 or chunk.direction != 'orig':
            return ()
        buf = self.buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        if len(buf) > self.max_buffer:
            del buf[:-self.max_buffer]
        findings: list[Finding] = []
        while True:
            outer = read_tlv(bytes(buf), 0)
            if not outer:
                break
            if outer.tag != 0x30:
                del buf[:1]
                continue
            findings.extend(self._parse_ldap_message(chunk, outer.value))
            del buf[:outer.end]
        return findings

    def on_udp(self, datagram: UDPDatagram) -> Iterable[Finding]:
        if datagram.src.port not in {161, 162} and datagram.dst.port not in {161, 162}:
            return ()
        finding = self._parse_snmp(datagram)
        return [finding] if finding else ()

    def _parse_ldap_message(self, chunk: TCPChunk, body: bytes) -> list[Finding]:
        msg_id = read_tlv(body, 0)
        if not msg_id or msg_id.tag != 0x02:
            return []
        op = read_tlv(body, msg_id.end)
        if not op:
            return []
        if op.tag == 0x60:  # BindRequest
            version = read_tlv(op.value, 0)
            name = read_tlv(op.value, version.end if version else 0)
            auth = read_tlv(op.value, name.end if name else 0)
            if not version or not name or not auth or name.tag != 0x04:
                return []
            dn = safe_decode(name.value)
            if auth.tag == 0x80:
                password = safe_decode(auth.value)
                return [Finding(
                    timestamp=chunk.timestamp, protocol='LDAP', category='cleartext_credential',
                    severity='high', title='LDAP Simple Bind password exposed',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    username=dn, secret=password, secret_type='password',
                    evidence='LDAP BindRequest using simple authentication',
                    metadata={'ldap_version': integer_value(version), 'bind_dn': dn},
                )]
        elif op.tag == 0x77 and b'1.3.6.1.4.1.1466.20037' in op.value:
            return [Finding(
                timestamp=chunk.timestamp, protocol='LDAP', category='transport_upgrade',
                severity='info', title='LDAP StartTLS requested', src=chunk.src, dst=chunk.dst,
                flow_id=chunk.flow.flow_id, evidence='LDAP StartTLS extended operation',
            )]
        return []

    @staticmethod
    def _parse_snmp(datagram: UDPDatagram) -> Finding | None:
        outer = read_tlv(datagram.data, 0)
        if not outer or outer.tag != 0x30:
            return None
        version_tlv = read_tlv(outer.value, 0)
        if not version_tlv or version_tlv.tag != 0x02:
            return None
        community_tlv = read_tlv(outer.value, version_tlv.end)
        if not community_tlv or community_tlv.tag != 0x04:
            return None
        version_num = integer_value(version_tlv)
        if version_num not in {0, 1}:
            return None
        community = safe_decode(community_tlv.value)
        if not community or not community.isprintable():
            return None
        version = 'SNMPv1' if version_num == 0 else 'SNMPv2c'
        return Finding(
            timestamp=datagram.timestamp, protocol=version, category='cleartext_credential',
            severity='high', title=f'{version} community string exposed',
            src=datagram.src, dst=datagram.dst, secret=community,
            secret_type='community_string', evidence=f'{version} message community field',
            metadata={'snmp_version': version_num},
        )
