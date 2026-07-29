from __future__ import annotations

import hashlib
import re
import struct
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from .base import Detector, printable_ratio, safe_decode
from ..models import Finding, TCPChunk


@dataclass
class PostgreSQLState:
    buffers: dict[str, bytearray] = field(default_factory=lambda: {'orig': bytearray(), 'resp': bytearray()})
    username: str = ''
    database: str = ''
    auth_mode: int = -1
    salt: bytes = b''
    encrypted: bool = False
    ssl_requested: bool = False
    startup_done: bool = False


@dataclass
class MySQLState:
    buffers: dict[str, bytearray] = field(default_factory=lambda: {'orig': bytearray(), 'resp': bytearray()})
    scramble: bytes = b''
    plugin: str = ''
    server_version: str = ''
    capabilities: int = 0
    handshake_seen: bool = False
    encrypted: bool = False


@dataclass
class MSSQLState:
    buffer: bytearray = field(default_factory=bytearray)
    encrypted: bool = False


class DatabaseDetector(Detector):
    name = 'databases'

    def __init__(self):
        self.pg: dict[str, PostgreSQLState] = defaultdict(PostgreSQLState)
        self.mysql: dict[str, MySQLState] = defaultdict(MySQLState)
        self.mssql: dict[str, MSSQLState] = defaultdict(MSSQLState)
        self.redis_buffers: dict[str, bytearray] = defaultdict(bytearray)

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        port = chunk.flow.service_port
        if port == 5432:
            return self._postgresql(chunk)
        if port == 3306:
            return self._mysql(chunk)
        if port == 1433:
            return self._mssql(chunk)
        if port == 6379:
            return self._redis(chunk)
        return ()

    def _postgresql(self, chunk: TCPChunk) -> list[Finding]:
        state = self.pg[chunk.flow.flow_id]
        if state.encrypted:
            return []
        buf = state.buffers[chunk.direction]
        buf.extend(chunk.data)
        findings: list[Finding] = []

        if chunk.direction == 'orig' and not state.startup_done:
            while len(buf) >= 8:
                length = struct.unpack('!I', buf[:4])[0]
                if length < 8 or length > 1024 * 1024 or len(buf) < length:
                    break
                code = struct.unpack('!I', buf[4:8])[0]
                packet = bytes(buf[:length])
                del buf[:length]
                if length == 8 and code == 80877103:  # SSLRequest
                    state.ssl_requested = True
                    continue
                if code == 196608:  # protocol 3.0 startup
                    params = packet[8:].split(b'\x00')
                    for i in range(0, len(params) - 1, 2):
                        key = safe_decode(params[i])
                        value = safe_decode(params[i + 1])
                        if key == 'user':
                            state.username = value
                        elif key == 'database':
                            state.database = value
                    state.startup_done = True
                    break
                # CancelRequest or unsupported startup packet.

        if chunk.direction == 'resp' and state.ssl_requested and buf:
            response = bytes(buf[:1])
            del buf[:1]
            state.ssl_requested = False
            if response == b'S':
                state.encrypted = True
                return []

        if not state.startup_done or state.encrypted:
            return findings

        while len(buf) >= 5:
            msg_type = chr(buf[0])
            length = struct.unpack('!I', buf[1:5])[0]
            total = 1 + length
            if length < 4 or length > 16 * 1024 * 1024 or len(buf) < total:
                break
            payload = bytes(buf[5:total])
            del buf[:total]
            if chunk.direction == 'resp' and msg_type == 'R' and len(payload) >= 4:
                state.auth_mode = struct.unpack('!I', payload[:4])[0]
                if state.auth_mode == 5 and len(payload) >= 8:
                    state.salt = payload[4:8]
            elif chunk.direction == 'orig' and msg_type == 'p':
                findings.extend(self._postgres_password(chunk, state, payload))
        return findings

    def _postgres_password(self, chunk: TCPChunk, state: PostgreSQLState, payload: bytes) -> list[Finding]:
        value = payload.rstrip(b'\x00')
        if state.auth_mode == 3:
            password = safe_decode(value)
            return [Finding(
                timestamp=chunk.timestamp, protocol='PostgreSQL', category='cleartext_credential',
                severity='high', title='PostgreSQL cleartext PasswordMessage exposed',
                src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                username=state.username, secret=password, secret_type='password',
                evidence=f'AuthenticationCleartextPassword for database {state.database or "unknown"}',
                metadata={'database': state.database, 'auth_method': 'cleartext'},
            )]
        if state.auth_mode == 5:
            response = safe_decode(value)
            return [Finding(
                timestamp=chunk.timestamp, protocol='PostgreSQL', category='challenge_response',
                severity='medium', title='PostgreSQL MD5 authentication response captured',
                src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                username=state.username, secret=response, secret_type='postgres_md5_response',
                evidence=f'AuthenticationMD5Password salt={state.salt.hex()}',
                metadata={'database': state.database, 'salt': state.salt.hex(), 'response': response,
                          'hashcat': f'{state.username}:$postgres${state.salt.hex()}${response}',
                          'hash_file': 'PostgreSQL-MD5.txt'},
            )]
        if state.auth_mode in {10, 11, 12}:
            text = safe_decode(value)
            user_match = re.search(r'n=([^,]+)', text)
            proof_match = re.search(r'p=([^,]+)', text)
            return [Finding(
                timestamp=chunk.timestamp, protocol='PostgreSQL', category='challenge_response',
                severity='low', title='PostgreSQL SCRAM authentication exchange observed',
                src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                username=user_match.group(1) if user_match else state.username,
                secret=proof_match.group(1) if proof_match else '', secret_type='scram_client_proof',
                evidence='SASL/SCRAM PasswordMessage', metadata={'database': state.database, 'message': text[:1000]},
            )]
        return []

    def _mysql(self, chunk: TCPChunk) -> list[Finding]:
        state = self.mysql[chunk.flow.flow_id]
        if state.encrypted:
            return []
        buf = state.buffers[chunk.direction]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while len(buf) >= 4:
            length = int.from_bytes(buf[:3], 'little')
            total = 4 + length
            if length > 16 * 1024 * 1024 or len(buf) < total:
                break
            seq = buf[3]
            payload = bytes(buf[4:total])
            del buf[:total]
            if chunk.direction == 'resp' and not state.handshake_seen and payload[:1] == b'\x0a':
                self._parse_mysql_handshake(state, payload)
            elif chunk.direction == 'orig' and state.handshake_seen:
                finding = self._parse_mysql_response(chunk, state, payload)
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def _parse_mysql_handshake(state: MySQLState, payload: bytes) -> None:
        try:
            pos = 1
            end = payload.index(0, pos)
            state.server_version = safe_decode(payload[pos:end])
            pos = end + 1 + 4
            part1 = payload[pos:pos + 8]
            pos += 8 + 1
            if pos + 2 > len(payload):
                return
            cap_low = int.from_bytes(payload[pos:pos + 2], 'little')
            pos += 2
            if pos >= len(payload):
                state.capabilities = cap_low
                state.scramble = part1
                state.handshake_seen = True
                return
            pos += 1 + 2
            cap_high = int.from_bytes(payload[pos:pos + 2], 'little')
            state.capabilities = cap_low | (cap_high << 16)
            pos += 2
            auth_len = payload[pos] if pos < len(payload) else 0
            pos += 1 + 10
            part2_len = max(13, auth_len - 8) if auth_len else 13
            part2 = payload[pos:pos + part2_len].rstrip(b'\x00')
            pos += part2_len
            state.scramble = (part1 + part2)[:20]
            if pos < len(payload):
                state.plugin = safe_decode(payload[pos:].split(b'\x00', 1)[0])
            state.handshake_seen = True
        except (ValueError, IndexError):
            return

    def _parse_mysql_response(self, chunk: TCPChunk, state: MySQLState, payload: bytes) -> Finding | None:
        if len(payload) < 32:
            return None
        capabilities = int.from_bytes(payload[:4], 'little')
        CLIENT_SSL = 0x00000800
        CLIENT_CONNECT_WITH_DB = 0x00000008
        CLIENT_SECURE_CONNECTION = 0x00008000
        CLIENT_PLUGIN_AUTH = 0x00080000
        CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000
        if capabilities & CLIENT_SSL and len(payload) == 32:
            state.encrypted = True
            return None
        pos = 32
        try:
            end = payload.index(0, pos)
        except ValueError:
            return None
        username = safe_decode(payload[pos:end])
        pos = end + 1
        auth_response = b''
        if capabilities & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA:
            length, consumed = self._read_lenenc(payload, pos)
            if length is None:
                return None
            pos += consumed
            auth_response = payload[pos:pos + length]
            pos += length
        elif capabilities & CLIENT_SECURE_CONNECTION:
            if pos >= len(payload):
                return None
            length = payload[pos]
            pos += 1
            auth_response = payload[pos:pos + length]
            pos += length
        else:
            try:
                end = payload.index(0, pos)
            except ValueError:
                end = len(payload)
            auth_response = payload[pos:end]
            pos = end + 1
        if capabilities & CLIENT_CONNECT_WITH_DB:
            try:
                pos = payload.index(0, pos) + 1
            except ValueError:
                return None
        plugin = state.plugin
        if capabilities & CLIENT_PLUGIN_AUTH and pos < len(payload):
            plugin = safe_decode(payload[pos:].split(b'\x00', 1)[0]) or plugin

        if plugin == 'mysql_clear_password':
            password = safe_decode(auth_response.rstrip(b'\x00'))
            return Finding(
                timestamp=chunk.timestamp, protocol='MySQL', category='cleartext_credential',
                severity='high', title='MySQL cleartext authentication plugin password exposed',
                src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                username=username, secret=password, secret_type='password',
                evidence=f'MySQL plugin={plugin}', metadata={'plugin': plugin, 'server_version': state.server_version},
            )
        if auth_response:
            response_hex = auth_response.hex()
            return Finding(
                timestamp=chunk.timestamp, protocol='MySQL', category='challenge_response',
                severity='medium', title='MySQL authentication challenge-response captured',
                src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                username=username, secret=response_hex, secret_type='mysql_auth_response',
                evidence=f'MySQL plugin={plugin or "unknown"}',
                metadata={'plugin': plugin, 'server_version': state.server_version,
                          'scramble': state.scramble.hex(), 'response': response_hex,
                          'hash_file': 'MySQL-Auth.txt',
                          'hashcat': f'{username}:{plugin}:{state.scramble.hex()}:{response_hex}'},
            )
        return None

    @staticmethod
    def _read_lenenc(data: bytes, pos: int) -> tuple[int | None, int]:
        if pos >= len(data):
            return None, 0
        first = data[pos]
        if first < 0xFB:
            return first, 1
        if first == 0xFC and pos + 3 <= len(data):
            return int.from_bytes(data[pos + 1:pos + 3], 'little'), 3
        if first == 0xFD and pos + 4 <= len(data):
            return int.from_bytes(data[pos + 1:pos + 4], 'little'), 4
        if first == 0xFE and pos + 9 <= len(data):
            return int.from_bytes(data[pos + 1:pos + 9], 'little'), 9
        return None, 0

    def _mssql(self, chunk: TCPChunk) -> list[Finding]:
        if chunk.direction != 'orig':
            return []
        state = self.mssql[chunk.flow.flow_id]
        if state.encrypted:
            return []
        state.buffer.extend(chunk.data)
        findings: list[Finding] = []
        while len(state.buffer) >= 8:
            packet_type = state.buffer[0]
            length = int.from_bytes(state.buffer[2:4], 'big')
            if length < 8 or length > 131071 or len(state.buffer) < length:
                break
            payload = bytes(state.buffer[8:length])
            del state.buffer[:length]
            if packet_type == 0x12 and payload.startswith(b'\x16\x03'):
                state.encrypted = True
                continue
            if packet_type == 0x10:
                finding = self._parse_login7(chunk, payload)
                if finding:
                    findings.append(finding)
        return findings

    @staticmethod
    def _deobfuscate_tds_password(raw: bytes) -> str:
        decoded = bytearray()
        for byte in raw:
            value = byte ^ 0xA5
            decoded.append(((value & 0x0F) << 4) | ((value & 0xF0) >> 4))
        return decoded.decode('utf-16le', errors='replace').rstrip('\x00')

    def _parse_login7(self, chunk: TCPChunk, payload: bytes) -> Finding | None:
        if len(payload) < 48:
            return None
        total_len = int.from_bytes(payload[0:4], 'little')
        if total_len > len(payload) or total_len < 48:
            return None
        option_flags2 = payload[25]
        integrated_security = bool(option_flags2 & 0x80)
        if integrated_security:
            return None
        user_off, user_chars = struct.unpack_from('<HH', payload, 40)
        pwd_off, pwd_chars = struct.unpack_from('<HH', payload, 44)
        if user_chars > 128 or pwd_chars > 128:
            return None
        user_end = user_off + user_chars * 2
        pwd_end = pwd_off + pwd_chars * 2
        if user_end > len(payload) or pwd_end > len(payload):
            return None
        username = payload[user_off:user_end].decode('utf-16le', errors='replace')
        password = self._deobfuscate_tds_password(payload[pwd_off:pwd_end])
        if not username and not password:
            return None
        return Finding(
            timestamp=chunk.timestamp, protocol='MSSQL', category='cleartext_credential',
            severity='critical', title='MSSQL LOGIN7 password reversibly exposed',
            src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
            username=username, secret=password, secret_type='password',
            evidence='TDS LOGIN7 username/password fields', metadata={'tds_login7_length': total_len},
        )

    def _redis(self, chunk: TCPChunk) -> list[Finding]:
        if chunk.direction != 'orig':
            return []
        buf = self.redis_buffers[chunk.flow.flow_id]
        buf.extend(chunk.data)
        findings: list[Finding] = []
        while buf:
            parsed = self._parse_resp_command(bytes(buf))
            if parsed is None:
                # Inline command fallback.
                line_end = buf.find(b'\n')
                if line_end < 0:
                    break
                line = safe_decode(bytes(buf[:line_end + 1]).strip())
                del buf[:line_end + 1]
                parts = line.split()
                consumed = 0
            else:
                parts, consumed = parsed
                del buf[:consumed]
            if not parts:
                continue
            if parts[0].upper() == 'AUTH':
                if len(parts) == 2:
                    username, password = 'default', parts[1]
                elif len(parts) >= 3:
                    username, password = parts[1], parts[2]
                else:
                    continue
                findings.append(Finding(
                    timestamp=chunk.timestamp, protocol='Redis', category='cleartext_credential',
                    severity='critical', title='Redis AUTH credential exposed',
                    src=chunk.src, dst=chunk.dst, flow_id=chunk.flow.flow_id,
                    username=username, secret=password, secret_type='password',
                    evidence='Redis AUTH command', metadata={'command_arity': len(parts)},
                ))
        if len(buf) > 4 * 1024 * 1024:
            del buf[:-1024]
        return findings

    @staticmethod
    def _parse_resp_command(data: bytes) -> tuple[list[str], int] | None:
        if not data.startswith(b'*'):
            return None
        line_end = data.find(b'\r\n')
        if line_end < 0:
            return None
        try:
            count = int(data[1:line_end])
        except ValueError:
            return None
        pos = line_end + 2
        parts: list[str] = []
        for _ in range(count):
            if pos >= len(data) or data[pos:pos + 1] != b'$':
                return None
            line_end = data.find(b'\r\n', pos)
            if line_end < 0:
                return None
            try:
                length = int(data[pos + 1:line_end])
            except ValueError:
                return None
            pos = line_end + 2
            if length < 0 or pos + length + 2 > len(data):
                return None
            parts.append(safe_decode(data[pos:pos + length]))
            pos += length + 2
        return parts, pos
