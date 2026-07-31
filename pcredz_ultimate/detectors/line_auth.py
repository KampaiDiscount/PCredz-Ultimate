from __future__ import annotations

import re
import shlex
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .base import Detector, decode_base64_loose, parse_sasl_plain, safe_decode
from ..models import Finding, TCPChunk


LINE_PORTS = {
    21: 'FTP', 23: 'TELNET', 25: 'SMTP', 110: 'POP3', 119: 'NNTP', 143: 'IMAP',
    587: 'SMTP', 6667: 'IRC', 6668: 'IRC', 6669: 'IRC', 7000: 'IRC',
}


@dataclass
class LineState:
    protocol: str = ''
    buffers: dict[str, bytearray] = field(default_factory=lambda: {'orig': bytearray(), 'resp': bytearray()})
    username: str = ''
    auth_mode: str = ''
    auth_stage: int = 0
    auth_challenge: str = ''
    starttls_requested: bool = False
    encrypted: bool = False
    pop3_challenge: str = ''
    telnet_expect: str = ''
    telnet_username: str = ''


class LineAuthDetector(Detector):
    name = 'line-auth'

    def __init__(self, max_line: int = 16384):
        self.states: dict[str, LineState] = defaultdict(LineState)
        self.max_line = max_line

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        state = self.states[chunk.flow.flow_id]

        # The line-oriented parser is deliberately broad so it can identify mail,
        # FTP, IRC and Telnet on non-standard ports.  Do not let that heuristic
        # reinterpret an already identified HTTP/TLS flow as Telnet merely because
        # an HTML response contains a line such as "Password:".
        if state.protocol == 'IGNORE' or chunk.flow.protocol_hint in {'http', 'tls'}:
            state.protocol = 'IGNORE'
            state.buffers['orig'].clear()
            state.buffers['resp'].clear()
            return ()

        if not state.protocol and self._looks_like_http(chunk.data):
            state.protocol = 'IGNORE'
            state.buffers['orig'].clear()
            state.buffers['resp'].clear()
            return ()

        if not state.protocol:
            state.protocol = LINE_PORTS.get(chunk.flow.service_port, '')
        if state.encrypted:
            return ()
        data = self._strip_telnet_iac(chunk.data) if state.protocol == 'TELNET' else chunk.data
        buf = state.buffers[chunk.direction]
        buf.extend(data)
        if len(buf) > self.max_line * 8:
            del buf[:-self.max_line * 4]
        findings: list[Finding] = []
        while True:
            newline = buf.find(b'\n')
            if newline < 0:
                break
            raw = bytes(buf[:newline + 1])
            del buf[:newline + 1]
            line = safe_decode(raw.rstrip(b'\r\n')).strip()
            if len(line) > self.max_line:
                continue
            if not state.protocol:
                state.protocol = self._classify(line, chunk.direction)
            if not state.protocol:
                continue
            findings.extend(self._process_line(state, chunk, line))
        return findings

    @staticmethod
    def _looks_like_http(data: bytes) -> bool:
        sample = data.lstrip()[:256].upper()
        if sample.startswith((b'HTTP/', b'RTSP/', b'SIP/')):
            return True
        return any(sample.startswith(method + b' ') for method in (
            b'GET', b'HEAD', b'POST', b'PUT', b'PATCH', b'DELETE',
            b'OPTIONS', b'CONNECT', b'TRACE', b'PROPFIND', b'PROPPATCH',
            b'MKCOL', b'COPY', b'MOVE', b'LOCK', b'UNLOCK',
        ))

    @staticmethod
    def _classify(line: str, direction: str) -> str:
        upper = line.upper()
        if upper.startswith(('220 ', 'EHLO ', 'HELO ', 'AUTH ')):
            return 'SMTP'
        if upper.startswith(('+OK', 'USER ', 'PASS ', 'APOP ')):
            return 'POP3'
        if re.match(r'^[A-Za-z0-9]+\s+(LOGIN|AUTHENTICATE|STARTTLS)\b', line, re.I):
            return 'IMAP'
        if upper.startswith(('USER ', 'PASS ', 'AUTH TLS', 'AUTH SSL')):
            return 'FTP'
        if upper.startswith(('AUTHINFO USER ', 'AUTHINFO PASS ')):
            return 'NNTP'
        if upper.startswith(('NICK ', 'JOIN ', 'CAP ', 'PASS ')):
            return 'IRC'
        if re.search(r'(?i)(login|username|password)\s*[:>]\s*$', line):
            return 'TELNET'
        return ''

    def _process_line(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        protocol = state.protocol
        if protocol == 'FTP':
            return self._ftp(state, chunk, line)
        if protocol == 'SMTP':
            return self._smtp(state, chunk, line)
        if protocol == 'IMAP':
            return self._imap(state, chunk, line)
        if protocol == 'POP3':
            return self._pop3(state, chunk, line)
        if protocol == 'NNTP':
            return self._nntp(state, chunk, line)
        if protocol == 'IRC':
            return self._irc(state, chunk, line)
        if protocol == 'TELNET':
            return self._telnet(state, chunk, line)
        return []

    def _ftp(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction == 'resp' and state.starttls_requested and line.startswith(('234', '334')):
            state.encrypted = True
            return []
        if chunk.direction != 'orig':
            return []
        upper = line.upper()
        if upper.startswith(('AUTH TLS', 'AUTH SSL')):
            state.starttls_requested = True
        elif upper.startswith('USER '):
            state.username = line[5:].strip()
        elif upper.startswith('PASS '):
            password = line[5:].strip()
            return [self._credential(chunk, 'FTP', state.username, password, 'FTP USER/PASS exposed', line)]
        return []

    def _smtp(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction == 'resp':
            if state.starttls_requested and line.startswith('220'):
                state.encrypted = True
            if state.auth_mode == 'CRAM-MD5' and line.startswith('334 '):
                decoded = decode_base64_loose(line[4:])
                state.auth_challenge = safe_decode(decoded) if decoded else line[4:]
            return []

        upper = line.upper()
        if upper == 'STARTTLS':
            state.starttls_requested = True
            return []
        if upper.startswith('AUTH '):
            parts = line.split(None, 2)
            if len(parts) < 2:
                return []
            state.auth_mode = parts[1].upper()
            state.auth_stage = 0
            initial = parts[2] if len(parts) > 2 else ''
            if state.auth_mode == 'PLAIN' and initial and initial != '=':
                return self._sasl_plain_finding(chunk, 'SMTP', initial, line)
            if state.auth_mode == 'LOGIN':
                if initial:
                    decoded = decode_base64_loose(initial)
                    state.username = safe_decode(decoded) if decoded else ''
                    state.auth_stage = 1
                return []
            if state.auth_mode in {'XOAUTH2', 'OAUTHBEARER'} and initial:
                return self._oauth_finding(chunk, 'SMTP', initial, line)
            return []

        if state.auth_mode == 'PLAIN':
            state.auth_mode = ''
            return self._sasl_plain_finding(chunk, 'SMTP', line, 'AUTH PLAIN continuation')
        if state.auth_mode == 'LOGIN':
            decoded = decode_base64_loose(line)
            text = safe_decode(decoded) if decoded else ''
            if state.auth_stage == 0:
                state.username = text
                state.auth_stage = 1
                return []
            state.auth_mode = ''
            state.auth_stage = 0
            return [self._credential(chunk, 'SMTP', state.username, text, 'SMTP AUTH LOGIN exposed', 'AUTH LOGIN exchange')]
        if state.auth_mode == 'CRAM-MD5':
            decoded = decode_base64_loose(line)
            response = safe_decode(decoded) if decoded else ''
            state.auth_mode = ''
            if ' ' in response:
                user, digest = response.split(' ', 1)
                return [Finding(
                    timestamp=chunk.timestamp, protocol='SMTP', category='challenge_response',
                    severity='medium', title='SMTP CRAM-MD5 challenge-response captured',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    username=user, secret=digest, secret_type='cram_md5_response',
                    evidence='AUTH CRAM-MD5 exchange',
                    metadata={'challenge': state.auth_challenge, 'response': digest,
                              'hashcat': f'{user}:$cram_md5${state.auth_challenge}${digest}',
                              'hash_file': 'SMTP-CRAM-MD5.txt'},
                )]
        if state.auth_mode in {'XOAUTH2', 'OAUTHBEARER'}:
            mode = state.auth_mode
            state.auth_mode = ''
            return self._oauth_finding(chunk, 'SMTP', line, f'AUTH {mode} continuation')
        return []

    def _imap(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction == 'resp':
            if state.starttls_requested and re.search(r'(?i)\bOK\b', line):
                state.encrypted = True
            return []
        try:
            parts = shlex.split(line)
        except ValueError:
            parts = line.split()
        if len(parts) < 2:
            return []
        command = parts[1].upper()
        if command == 'STARTTLS':
            state.starttls_requested = True
            return []
        if command == 'LOGIN' and len(parts) >= 4:
            return [self._credential(chunk, 'IMAP', parts[2], parts[3], 'IMAP LOGIN exposed', line)]
        if command == 'AUTHENTICATE' and len(parts) >= 3:
            state.auth_mode = parts[2].upper()
            state.auth_stage = 0
            if len(parts) >= 4:
                if state.auth_mode == 'PLAIN':
                    state.auth_mode = ''
                    return self._sasl_plain_finding(chunk, 'IMAP', parts[3], line)
                if state.auth_mode in {'XOAUTH2', 'OAUTHBEARER'}:
                    mode = state.auth_mode
                    state.auth_mode = ''
                    return self._oauth_finding(chunk, 'IMAP', parts[3], line)
            return []
        if state.auth_mode == 'PLAIN':
            state.auth_mode = ''
            return self._sasl_plain_finding(chunk, 'IMAP', line, 'AUTHENTICATE PLAIN continuation')
        if state.auth_mode in {'XOAUTH2', 'OAUTHBEARER'}:
            mode = state.auth_mode
            state.auth_mode = ''
            return self._oauth_finding(chunk, 'IMAP', line, f'AUTHENTICATE {mode} continuation')
        return []

    def _pop3(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction == 'resp':
            if not state.pop3_challenge:
                match = re.search(r'(<[^>]+>)', line)
                if match:
                    state.pop3_challenge = match.group(1)
            if state.starttls_requested and line.upper().startswith('+OK'):
                state.encrypted = True
            return []
        upper = line.upper()
        if upper == 'STLS':
            state.starttls_requested = True
        elif upper.startswith('USER '):
            state.username = line[5:].strip()
        elif upper.startswith('PASS '):
            return [self._credential(chunk, 'POP3', state.username, line[5:].strip(), 'POP3 USER/PASS exposed', line)]
        elif upper.startswith('APOP '):
            parts = line.split()
            if len(parts) >= 3:
                return [Finding(
                    timestamp=chunk.timestamp, protocol='POP3', category='challenge_response',
                    severity='medium', title='POP3 APOP challenge-response captured',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    username=parts[1], secret=parts[2], secret_type='apop_digest', evidence=line,
                    metadata={'challenge': state.pop3_challenge, 'digest': parts[2],
                              'hashcat': f'{state.pop3_challenge}:{parts[2]}',
                              'hash_file': 'POP3-APOP.txt'},
                )]
        return []

    def _nntp(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction != 'orig':
            return []
        upper = line.upper()
        if upper.startswith('AUTHINFO USER '):
            state.username = line[14:].strip()
        elif upper.startswith('AUTHINFO PASS '):
            return [self._credential(chunk, 'NNTP', state.username, line[14:].strip(), 'NNTP AUTHINFO exposed', line)]
        return []

    def _irc(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        if chunk.direction != 'orig':
            return []
        upper = line.upper()
        if upper.startswith('NICK '):
            state.username = line[5:].strip()
        elif upper.startswith('USER ') and not state.username:
            state.username = line[5:].split()[0] if line[5:].split() else ''
        elif upper.startswith('PASS '):
            return [self._credential(chunk, 'IRC', state.username, line[5:].strip(), 'IRC PASS exposed', line)]
        return []

    def _telnet(self, state: LineState, chunk: TCPChunk, line: str) -> list[Finding]:
        findings: list[Finding] = []
        if chunk.direction == 'resp':
            if re.search(r'(?i)(login|username|user name)\s*[:>]\s*$', line):
                state.telnet_expect = 'username'
            elif re.search(r'(?i)(password|passcode)\s*[:>]\s*$', line):
                state.telnet_expect = 'password'
            return findings
        if state.telnet_expect == 'username' and line:
            state.telnet_username = line
            state.telnet_expect = ''
        elif state.telnet_expect == 'password' and line:
            findings.append(self._credential(chunk, 'TELNET', state.telnet_username, line,
                                               'Telnet interactive password exposed', 'prompt/response authentication'))
            state.telnet_expect = ''
        return findings

    def _sasl_plain_finding(self, chunk: TCPChunk, protocol: str, encoded: str, evidence: str) -> list[Finding]:
        decoded = decode_base64_loose(encoded)
        parsed = parse_sasl_plain(decoded) if decoded else None
        if not parsed:
            return []
        authzid, authcid, password = parsed
        return [self._credential(chunk, protocol, authcid, password,
                                 f'{protocol} SASL PLAIN exposed', evidence,
                                 {'authzid': authzid})]

    def _oauth_finding(self, chunk: TCPChunk, protocol: str, encoded: str, evidence: str) -> list[Finding]:
        decoded = decode_base64_loose(encoded)
        if not decoded:
            return []
        text = safe_decode(decoded)
        user_match = re.search(r'(?i)(?:^|\x01)user=([^\x01]+)', text)
        token_match = re.search(r'(?i)(?:^|\x01)auth=Bearer\s+([^\x01]+)', text)
        if not token_match:
            return []
        return [Finding(
            timestamp=chunk.timestamp, protocol=protocol, category='session_token', severity='high',
            title=f'{protocol} OAuth bearer token exposed', src=chunk.src, dst=chunk.dst,
            flow_id=chunk.flow.flow_id, username=user_match.group(1) if user_match else '',
            secret=token_match.group(1), secret_type='oauth_bearer_token', evidence=evidence,
            metadata={'mechanism': 'XOAUTH2/OAUTHBEARER'},
        )]

    @staticmethod
    def _credential(chunk: TCPChunk, protocol: str, username: str, password: str,
                    title: str, evidence: str, metadata: dict | None = None) -> Finding:
        return Finding(
            timestamp=chunk.timestamp, protocol=protocol, category='cleartext_credential',
            severity='high', title=title, src=chunk.src, dst=chunk.dst,
            flow_id=chunk.flow.flow_id, username=username, secret=password,
            secret_type='password', evidence=evidence[:1000], metadata=metadata or {},
        )

    @staticmethod
    def _strip_telnet_iac(data: bytes) -> bytes:
        out = bytearray()
        i = 0
        while i < len(data):
            if data[i] != 0xFF:
                out.append(data[i])
                i += 1
                continue
            if i + 1 >= len(data):
                break
            command = data[i + 1]
            if command == 0xFF:
                out.append(0xFF)
                i += 2
            elif command in {0xFB, 0xFC, 0xFD, 0xFE}:
                i += 3
            elif command == 0xFA:
                end = data.find(b'\xff\xf0', i + 2)
                i = len(data) if end < 0 else end + 2
            else:
                i += 2
        return bytes(out)
