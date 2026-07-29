from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .base import Detector, safe_decode
from .ber import read_tlv, integer_value
from ..models import Finding, TCPChunk, UDPDatagram


class KerberosDetector(Detector):
    name = 'kerberos'

    def __init__(self):
        self.tcp_buffers: dict[str, bytearray] = defaultdict(bytearray)

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        if chunk.flow.service_port != 88 or chunk.direction != 'orig':
            return ()
        buf = self.tcp_buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while len(buf) >= 4:
            length = int.from_bytes(buf[:4], 'big')
            if length <= 0 or length > 4 * 1024 * 1024 or len(buf) < 4 + length:
                break
            message = bytes(buf[4:4 + length])
            del buf[:4 + length]
            finding = self._parse_as_req(message, chunk.timestamp, chunk.src, chunk.dst, chunk.flow.flow_id)
            if finding:
                findings.append(finding)
        return findings

    def on_udp(self, datagram: UDPDatagram) -> Iterable[Finding]:
        if datagram.src.port != 88 and datagram.dst.port != 88:
            return ()
        finding = self._parse_as_req(datagram.data, datagram.timestamp, datagram.src, datagram.dst, '')
        return [finding] if finding else ()

    def _parse_as_req(self, data: bytes, timestamp: float, src, dst, flow_id: str) -> Finding | None:
        outer = read_tlv(data, 0)
        if not outer or outer.tag != 0x6A:  # [APPLICATION 10] AS-REQ
            return None
        seq = read_tlv(outer.value, 0)
        if not seq or seq.tag != 0x30:
            return None
        padata_ctx = None
        req_body_ctx = None
        pos = 0
        while pos < len(seq.value):
            field = read_tlv(seq.value, pos)
            if not field:
                break
            if field.tag == 0xA3:
                padata_ctx = field
            elif field.tag == 0xA4:
                req_body_ctx = field
            pos = field.end
        username, realm = self._parse_req_body(req_body_ctx.value if req_body_ctx else b'')
        if not padata_ctx:
            return None
        encrypted = self._find_pa_enc_timestamp(padata_ctx.value)
        if not encrypted:
            return None
        etype, cipher = encrypted
        if etype != 23 or len(cipher) < 17:
            return Finding(
                timestamp=timestamp, protocol='Kerberos', category='preauthentication',
                severity='info', title=f'Kerberos PA-ENC-TIMESTAMP observed (etype {etype})',
                src=src, dst=dst, flow_id=flow_id, username=f'{username}@{realm}' if username else realm,
                secret=cipher.hex(), secret_type=f'kerberos_etype_{etype}_ciphertext',
                evidence='AS-REQ PA-ENC-TIMESTAMP', metadata={'etype': etype, 'realm': realm},
            )

        switched = cipher[16:] + cipher[:16]
        hash_line = f'$krb5pa$23${username}${realm.upper()}$dummy${switched.hex()}'
        return Finding(
            timestamp=timestamp, protocol='Kerberos', category='challenge_response',
            severity='high', title='Kerberos RC4 AS-REQ pre-authentication hash captured',
            src=src, dst=dst, flow_id=flow_id,
            username=f'{username}@{realm}' if username else realm,
            secret=hash_line, secret_type='krb5pa_etype23_hash',
            evidence='AS-REQ PA-ENC-TIMESTAMP etype 23',
            metadata={'etype': etype, 'realm': realm, 'ciphertext': cipher.hex(),
                      'hashcat': hash_line, 'hash_file': 'Kerberos-etype23-ASREQ.txt',
                      'hashcat_mode': 7500},
        )

    @staticmethod
    def _unwrap(value: bytes, expected_tag: int) -> bytes:
        tlv = read_tlv(value, 0)
        return tlv.value if tlv and tlv.tag == expected_tag else b''

    def _parse_req_body(self, value: bytes) -> tuple[str, str]:
        seq_value = self._unwrap(value, 0x30)
        username = ''
        realm = ''
        pos = 0
        while pos < len(seq_value):
            field = read_tlv(seq_value, pos)
            if not field:
                break
            if field.tag == 0xA1:  # cname
                principal_seq = self._unwrap(field.value, 0x30)
                ppos = 0
                while ppos < len(principal_seq):
                    pfield = read_tlv(principal_seq, ppos)
                    if not pfield:
                        break
                    if pfield.tag == 0xA1:
                        names_seq = self._unwrap(pfield.value, 0x30)
                        npos = 0
                        names = []
                        while npos < len(names_seq):
                            name = read_tlv(names_seq, npos)
                            if not name:
                                break
                            if name.tag in {0x1B, 0x0C, 0x16}:
                                names.append(safe_decode(name.value))
                            npos = name.end
                        username = '/'.join(names)
                    ppos = pfield.end
            elif field.tag == 0xA2:  # realm
                realm_tlv = read_tlv(field.value, 0)
                if realm_tlv and realm_tlv.tag in {0x1B, 0x0C, 0x16}:
                    realm = safe_decode(realm_tlv.value)
            pos = field.end
        return username, realm

    def _find_pa_enc_timestamp(self, value: bytes) -> tuple[int, bytes] | None:
        seq_of = self._unwrap(value, 0x30)
        pos = 0
        while pos < len(seq_of):
            pa = read_tlv(seq_of, pos)
            if not pa:
                break
            pos = pa.end
            if pa.tag != 0x30:
                continue
            pa_type = None
            pa_value = b''
            ppos = 0
            while ppos < len(pa.value):
                field = read_tlv(pa.value, ppos)
                if not field:
                    break
                if field.tag == 0xA1:
                    inner = read_tlv(field.value, 0)
                    if inner and inner.tag == 0x02:
                        pa_type = integer_value(inner)
                elif field.tag == 0xA2:
                    inner = read_tlv(field.value, 0)
                    if inner and inner.tag == 0x04:
                        pa_value = inner.value
                ppos = field.end
            if pa_type != 2 or not pa_value:
                continue
            encrypted_seq = read_tlv(pa_value, 0)
            if not encrypted_seq or encrypted_seq.tag != 0x30:
                continue
            etype = None
            cipher = b''
            epos = 0
            while epos < len(encrypted_seq.value):
                field = read_tlv(encrypted_seq.value, epos)
                if not field:
                    break
                if field.tag == 0xA0:
                    inner = read_tlv(field.value, 0)
                    if inner and inner.tag == 0x02:
                        etype = integer_value(inner)
                elif field.tag == 0xA2:
                    inner = read_tlv(field.value, 0)
                    if inner and inner.tag == 0x04:
                        cipher = inner.value
                epos = field.end
            if etype is not None and cipher:
                return etype, cipher
        return None
