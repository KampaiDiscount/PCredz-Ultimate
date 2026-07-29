from __future__ import annotations

import base64
import binascii
import re
import struct
from collections import defaultdict
from typing import Iterable

from .base import Detector, decode_base64_loose
from ..models import Finding, TCPChunk


AUTH_B64_RE = re.compile(
    rb'(?im)^(?:Authorization|Proxy-Authorization|WWW-Authenticate|Proxy-Authenticate):\s*'
    rb'(?:NTLM|Negotiate)\s+([A-Za-z0-9+/=]{16,})'
)


class NTLMDetector(Detector):
    name = 'ntlm'

    def __init__(self, max_buffer: int = 512 * 1024):
        self.buffers: dict[tuple[str, str], bytearray] = defaultdict(bytearray)
        self.challenges: dict[str, str] = {}
        self.max_buffer = max_buffer

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        key = (chunk.flow.flow_id, chunk.direction)
        buf = self.buffers[key]
        buf.extend(chunk.data)
        if len(buf) > self.max_buffer:
            del buf[:-self.max_buffer]
        findings: list[Finding] = []
        data = bytes(buf)

        # HTTP/SPNEGO wrappers often carry base64-encoded NTLM messages.
        for match in AUTH_B64_RE.finditer(data):
            decoded = decode_base64_loose(match.group(1))
            if decoded:
                findings.extend(self._scan_blob(chunk, decoded))

        findings.extend(self._scan_blob(chunk, data))
        return findings

    def _scan_blob(self, chunk: TCPChunk, data: bytes) -> list[Finding]:
        findings: list[Finding] = []
        pos = 0
        while True:
            idx = data.find(b'NTLMSSP\x00', pos)
            if idx < 0:
                break
            if idx + 12 > len(data):
                break
            try:
                msg_type = struct.unpack_from('<I', data, idx + 8)[0]
            except struct.error:
                break
            if msg_type == 2:
                if idx + 32 <= len(data):
                    challenge = data[idx + 24:idx + 32].hex().upper()
                    self.challenges[chunk.flow.flow_id] = challenge
                    findings.append(Finding(
                        timestamp=chunk.timestamp, protocol='NTLM', category='authentication_challenge',
                        severity='info', title='NTLM server challenge observed',
                        src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                        secret=challenge, secret_type='ntlm_challenge',
                        evidence=f'NTLMSSP Type 2 challenge {challenge}',
                        metadata={'message_type': 2, 'challenge': challenge},
                    ))
            elif msg_type == 3:
                finding = self._parse_type3(chunk, data[idx:])
                if finding:
                    findings.append(finding)
            pos = idx + 8
        return findings

    @staticmethod
    def _secbuf(blob: bytes, offset: int) -> tuple[int, int] | None:
        if offset + 8 > len(blob):
            return None
        length, max_length, data_offset = struct.unpack_from('<HHI', blob, offset)
        if length > max_length or data_offset + length > len(blob):
            return None
        return data_offset, length

    def _parse_type3(self, chunk: TCPChunk, blob: bytes) -> Finding | None:
        if len(blob) < 64:
            return None
        fields = {
            'lm': self._secbuf(blob, 12),
            'nt': self._secbuf(blob, 20),
            'domain': self._secbuf(blob, 28),
            'user': self._secbuf(blob, 36),
            'workstation': self._secbuf(blob, 44),
            'session_key': self._secbuf(blob, 52),
        }
        if not fields['nt'] or not fields['user']:
            return None

        def take(name: str) -> bytes:
            item = fields[name]
            if not item:
                return b''
            off, length = item
            return blob[off:off + length]

        user = take('user').decode('utf-16le', errors='replace').rstrip('\x00')
        domain = take('domain').decode('utf-16le', errors='replace').rstrip('\x00')
        workstation = take('workstation').decode('utf-16le', errors='replace').rstrip('\x00')
        lm_resp = take('lm').hex().upper()
        nt_resp = take('nt').hex().upper()
        nt_len = len(take('nt'))
        challenge = self.challenges.get(chunk.flow.flow_id, '')

        if not user and not nt_resp:
            return None
        metadata = {
            'message_type': 3,
            'domain': domain,
            'workstation': workstation,
            'challenge': challenge,
            'lm_response': lm_resp,
            'nt_response': nt_resp,
        }
        if nt_len > 24:
            version = 'NTLMv2'
            if challenge and len(nt_resp) >= 32:
                hash_line = f'{user}::{domain}:{challenge}:{nt_resp[:32]}:{nt_resp[32:]}'
                metadata.update({'hashcat': hash_line, 'hash_file': 'NTLMv2.txt', 'hashcat_mode': 5600})
                secret = hash_line
                severity = 'high'
                title = 'NetNTLMv2 challenge-response captured'
            else:
                secret = nt_resp
                severity = 'medium'
                title = 'Incomplete NetNTLMv2 response captured'
        elif nt_len == 24:
            version = 'NTLMv1'
            if challenge:
                hash_line = f'{user}::{domain}:{lm_resp}:{nt_resp}:{challenge}'
                metadata.update({'hashcat': hash_line, 'hash_file': 'NTLMv1.txt', 'hashcat_mode': 5500})
                secret = hash_line
                severity = 'critical'
                title = 'NetNTLMv1 challenge-response captured'
            else:
                secret = nt_resp
                severity = 'high'
                title = 'Incomplete NetNTLMv1 response captured'
        else:
            version = 'NTLM'
            secret = nt_resp
            severity = 'medium'
            title = 'NTLM authentication response captured'

        metadata['version'] = version
        return Finding(
            timestamp=chunk.timestamp, protocol='NTLM', category='challenge_response',
            severity=severity, title=title, src=chunk.src, dst=chunk.dst,
            flow_id=chunk.flow.flow_id, username=f'{domain}\\{user}' if domain else user,
            secret=secret, secret_type=version.lower() + '_hash',
            evidence=f'NTLMSSP Type 3 from workstation {workstation or "unknown"}',
            metadata=metadata,
        )
