from __future__ import annotations

import gzip
import json
import re
import zlib
from collections import defaultdict
from typing import Iterable
from urllib.parse import parse_qsl, unquote, urlsplit

from .base import (
    Detector, AWS_ACCESS_KEY_RE, GENERIC_BEARER_RE, JWT_RE,
    decode_base64_loose, extract_structured_credentials, flatten_json,
    parse_http_digest, parse_multipart, safe_decode,
)
from ..inventory import Inventory
from ..models import Finding, TCPChunk


HTTP_METHODS = {
    'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE',
    'PROPFIND', 'PROPPATCH', 'MKCOL', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
    'REGISTER', 'INVITE', 'ACK', 'BYE', 'CANCEL', 'MESSAGE', 'SUBSCRIBE', 'NOTIFY',
    'PUBLISH', 'DESCRIBE', 'ANNOUNCE', 'SETUP', 'PLAY', 'PAUSE', 'TEARDOWN',
}
HTTP_PORTS = {80, 81, 3000, 5000, 5985, 8000, 8008, 8080, 8081, 8888, 9200}
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443, 8883}
TOKEN_HEADERS = {
    'x-api-key', 'x-auth-token', 'x-access-token', 'x-amz-security-token',
    'private-token', 'x-gitlab-token', 'x-csrf-token', 'x-xsrf-token',
}
SESSION_COOKIE_RE = re.compile(r'(?i)(session|sessid|sid|auth|token|jwt|bearer|sso|remember)')
BOUNDARY_RE = re.compile(r'boundary=(?:"([^"]+)"|([^;]+))', re.I)


class HTTPDetector(Detector):
    name = 'http'

    def __init__(self, inventory: Inventory, max_buffer: int = 4 * 1024 * 1024):
        self.inventory = inventory
        self.buffers: dict[tuple[str, str], bytearray] = defaultdict(bytearray)
        self.max_buffer = max_buffer

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        if chunk.flow.service_port in TLS_PORTS:
            return ()
        key = (chunk.flow.flow_id, chunk.direction)
        buf = self.buffers[key]
        buf.extend(chunk.data)
        if len(buf) > self.max_buffer:
            del buf[:-self.max_buffer]
        findings: list[Finding] = []
        for message in self._drain_messages(buf):
            findings.extend(self._analyze_message(chunk, message))
        return findings

    def _drain_messages(self, buf: bytearray) -> list[dict]:
        messages: list[dict] = []
        while True:
            if len(buf) < 8:
                break
            start = self._find_start(buf)
            if start is None:
                if len(buf) > 8192:
                    del buf[:-4096]
                break
            if start > 0:
                del buf[:start]
            header_end = bytes(buf).find(b'\r\n\r\n')
            sep_len = 4
            if header_end < 0:
                header_end = bytes(buf).find(b'\n\n')
                sep_len = 2
            if header_end < 0:
                break
            header_blob = bytes(buf[:header_end])
            lines = re.split(br'\r?\n', header_blob)
            if not lines:
                del buf[:1]
                continue
            start_line = safe_decode(lines[0]).strip()
            headers: dict[str, str] = {}
            for raw in lines[1:]:
                if b':' not in raw:
                    continue
                k, v = raw.split(b':', 1)
                key = safe_decode(k).strip().lower()
                value = safe_decode(v).strip()
                if key in headers:
                    # Set-Cookie is not comma-combinable; preserve one value per line.
                    headers[key] += ('\n' if key == 'set-cookie' else ', ') + value
                else:
                    headers[key] = value

            body_start = header_end + sep_len
            body_length = 0
            chunked = 'chunked' in headers.get('transfer-encoding', '').lower()
            if 'content-length' in headers:
                try:
                    body_length = int(headers['content-length'])
                except ValueError:
                    body_length = 0
            if chunked:
                decoded = self._decode_chunked(bytes(buf[body_start:]))
                if decoded is None:
                    break
                body, consumed = decoded
                total = body_start + consumed
            else:
                total = body_start + body_length
                if len(buf) < total:
                    break
                body = bytes(buf[body_start:total])

            raw = bytes(buf[:total])
            del buf[:total]
            kind = 'response' if start_line.upper().startswith(('HTTP/', 'RTSP/', 'SIP/')) else 'request'
            messages.append({
                'kind': kind,
                'start_line': start_line,
                'headers': headers,
                'body': self._decompress_body(body, headers),
                'raw': raw,
            })
        return messages

    @staticmethod
    def _find_start(buf: bytearray) -> int | None:
        raw = bytes(buf)
        candidates: list[int] = []
        for prefix in [b'HTTP/', b'RTSP/', b'SIP/'] + [m.encode() + b' ' for m in HTTP_METHODS]:
            pos = raw.find(prefix)
            if pos >= 0:
                candidates.append(pos)
        return min(candidates) if candidates else None

    @staticmethod
    def _decode_chunked(data: bytes) -> tuple[bytes, int] | None:
        pos = 0
        out = bytearray()
        while True:
            line_end = data.find(b'\r\n', pos)
            if line_end < 0:
                return None
            size_line = data[pos:line_end].split(b';', 1)[0].strip()
            try:
                size = int(size_line, 16)
            except ValueError:
                return None
            pos = line_end + 2
            if size == 0:
                trailer_end = data.find(b'\r\n\r\n', pos)
                if trailer_end >= 0:
                    return bytes(out), trailer_end + 4
                if len(data) >= pos + 2 and data[pos:pos + 2] == b'\r\n':
                    return bytes(out), pos + 2
                return None
            if len(data) < pos + size + 2:
                return None
            out.extend(data[pos:pos + size])
            pos += size
            if data[pos:pos + 2] != b'\r\n':
                return None
            pos += 2

    @staticmethod
    def _decompress_body(body: bytes, headers: dict[str, str]) -> bytes:
        encoding = headers.get('content-encoding', '').lower()
        try:
            if 'gzip' in encoding:
                return gzip.decompress(body)
            if 'deflate' in encoding:
                try:
                    return zlib.decompress(body)
                except zlib.error:
                    return zlib.decompress(body, -zlib.MAX_WBITS)
        except Exception:
            return body
        return body

    def _analyze_message(self, chunk: TCPChunk, message: dict) -> list[Finding]:
        findings: list[Finding] = []
        start_line = message['start_line']
        headers = message['headers']
        body = message['body']
        kind = message['kind']
        host = headers.get('host', '')
        if host:
            self.inventory.add_http_host(host)
        if headers.get('user-agent'):
            self.inventory.add_user_agent(headers['user-agent'])

        protocol = 'HTTP'
        upper = start_line.upper()
        if upper.startswith(('REGISTER ', 'INVITE ', 'SIP/')):
            protocol = 'SIP'
        elif upper.startswith(('DESCRIBE ', 'SETUP ', 'PLAY ', 'RTSP/')):
            protocol = 'RTSP'

        if kind == 'request':
            parts = start_line.split()
            method = parts[0] if parts else ''
            target = parts[1] if len(parts) > 1 else ''
            context = f'{method} {host}{target}'.strip()
            findings.extend(self._extract_auth_headers(chunk, protocol, headers, method, target, context))
            findings.extend(self._extract_cookie_tokens(chunk, protocol, headers, context))
            findings.extend(self._extract_query_and_body(chunk, protocol, headers, target, body, context))
        else:
            context = start_line
            findings.extend(self._extract_response_tokens(chunk, protocol, headers, body, context))
        return findings

    def _extract_auth_headers(self, chunk: TCPChunk, protocol: str, headers: dict[str, str],
                              method: str, target: str, context: str) -> list[Finding]:
        findings: list[Finding] = []
        for header_name in ('authorization', 'proxy-authorization'):
            value = headers.get(header_name, '')
            if not value:
                continue
            scheme, _, token = value.partition(' ')
            scheme_lower = scheme.lower()
            if scheme_lower == 'basic':
                decoded = decode_base64_loose(token)
                if decoded and b':' in decoded:
                    user_b, password_b = decoded.split(b':', 1)
                    user = safe_decode(user_b)
                    password = safe_decode(password_b)
                    findings.append(self._finding(chunk, protocol, 'cleartext_credential', 'high',
                        f'{protocol} Basic authentication exposed', user, password, 'password', context,
                        {'header': header_name, 'scheme': 'Basic'}))
            elif scheme_lower == 'bearer':
                findings.append(self._finding(chunk, protocol, 'session_token', 'high',
                    f'{protocol} bearer token exposed', '', token.strip(), 'bearer_token', context,
                    {'header': header_name, 'scheme': 'Bearer'}))
            elif scheme_lower == 'digest':
                fields = parse_http_digest(value)
                response = fields.get('response', '')
                if response:
                    hashcat = ':'.join([
                        fields.get('username', ''), fields.get('realm', ''), method,
                        fields.get('uri', target), fields.get('nonce', ''), fields.get('nc', ''),
                        fields.get('cnonce', ''), fields.get('qop', ''), response,
                    ])
                    findings.append(self._finding(chunk, protocol, 'challenge_response', 'medium',
                        f'{protocol} Digest authentication captured', fields.get('username', ''),
                        response, 'digest_response', context,
                        {'digest': fields, 'hashcat': hashcat, 'hash_file': 'HTTP-Digest.txt'}))
            elif scheme_lower in {'ntlm', 'negotiate'}:
                # Generic NTLM detector handles the embedded NTLMSSP blob.
                pass
            else:
                findings.append(self._finding(chunk, protocol, 'authentication_token', 'medium',
                    f'{protocol} authorization credential exposed', '', token.strip() or value,
                    f'{scheme_lower}_token', context, {'header': header_name, 'scheme': scheme}))

        for header_name in TOKEN_HEADERS:
            value = headers.get(header_name)
            if value:
                findings.append(self._finding(chunk, protocol, 'authentication_token', 'high',
                    f'{protocol} API/session header exposed', '', value, header_name, context,
                    {'header': header_name}))
        return findings

    def _extract_cookie_tokens(self, chunk: TCPChunk, protocol: str, headers: dict[str, str],
                               context: str) -> list[Finding]:
        findings: list[Finding] = []
        cookie = headers.get('cookie', '')
        for piece in cookie.split(';'):
            if '=' not in piece:
                continue
            key, value = piece.split('=', 1)
            key, value = key.strip(), value.strip()
            if key and value and SESSION_COOKIE_RE.search(key):
                findings.append(self._finding(chunk, protocol, 'session_cookie', 'high',
                    f'{protocol} session cookie exposed', '', value, key, context,
                    {'cookie_name': key}))
        return findings

    def _extract_query_and_body(self, chunk: TCPChunk, protocol: str, headers: dict[str, str],
                                target: str, body: bytes, context: str) -> list[Finding]:
        findings: list[Finding] = []
        items: list[tuple[str, str]] = []
        try:
            parsed_target = urlsplit(target)
            query = parsed_target.query
            if query:
                items.extend(parse_qsl(query, keep_blank_values=True))
            if parsed_target.username is not None and parsed_target.password is not None:
                findings.append(self._finding(
                    chunk, protocol, 'cleartext_credential', 'high',
                    f'{protocol} URI userinfo credential exposed',
                    unquote(parsed_target.username), unquote(parsed_target.password),
                    'password', context, {'location': 'request_target_userinfo'},
                ))
        except ValueError:
            pass

        content_type = headers.get('content-type', '').lower()
        if body:
            if 'application/x-www-form-urlencoded' in content_type:
                items.extend(parse_qsl(safe_decode(body), keep_blank_values=True))
            elif 'application/json' in content_type or body.lstrip().startswith((b'{', b'[')):
                try:
                    items.extend(flatten_json(json.loads(safe_decode(body))))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            elif 'multipart/form-data' in content_type:
                match = BOUNDARY_RE.search(content_type)
                if match:
                    items.extend(parse_multipart(body, (match.group(1) or match.group(2)).strip()))
            elif 'xml' in content_type or body.lstrip().startswith(b'<'):
                text = safe_decode(body)
                items.extend(re.findall(r'<([A-Za-z0-9_.:-]+)[^>]*>([^<]{1,8192})</\1>', text))
            elif len(body) <= 1024 * 1024:
                text = safe_decode(body)
                items.extend(re.findall(r'(?i)([A-Za-z0-9_.\-]{2,80})\s*[=:]\s*["\']?([^&\s"\'<>]{1,8192})', text))

        for field, username, secret in extract_structured_credentials(items):
            findings.append(self._finding(chunk, protocol, 'cleartext_credential', 'high',
                f'{protocol} credential field exposed', username, secret, field, context,
                {'field': field, 'content_type': content_type}))

        for key, value in items:
            for match in JWT_RE.finditer(value):
                findings.append(self._finding(chunk, protocol, 'session_token', 'high',
                    f'{protocol} JWT exposed', '', match.group(0), 'jwt', context, {'field': key}))
            for match in AWS_ACCESS_KEY_RE.finditer(value):
                findings.append(self._finding(chunk, protocol, 'cloud_credential', 'critical',
                    f'{protocol} cloud access-key identifier exposed', '', match.group(0),
                    'aws_access_key_id', context, {'field': key}))
        return findings

    def _extract_response_tokens(self, chunk: TCPChunk, protocol: str, headers: dict[str, str],
                                 body: bytes, context: str) -> list[Finding]:
        findings: list[Finding] = []
        content_type = headers.get('content-type', '').lower()
        items: list[tuple[str, str]] = []
        if body and ('json' in content_type or body.lstrip().startswith((b'{', b'['))):
            try:
                items.extend(flatten_json(json.loads(safe_decode(body))))
            except json.JSONDecodeError:
                pass
        elif body and 'application/x-www-form-urlencoded' in content_type:
            items.extend(parse_qsl(safe_decode(body), keep_blank_values=True))
        for field, _, secret in extract_structured_credentials(items):
            findings.append(self._finding(chunk, protocol, 'authentication_token', 'high',
                f'{protocol} response credential/token exposed', '', secret, field, context,
                {'field': field, 'direction': 'response'}))
        set_cookie = headers.get('set-cookie', '')
        for cookie_line in set_cookie.splitlines():
            first = cookie_line.split(';', 1)[0]
            if '=' not in first:
                continue
            key, value = first.split('=', 1)
            key, value = key.strip(), value.strip()
            if SESSION_COOKIE_RE.search(key) and value:
                findings.append(self._finding(chunk, protocol, 'session_cookie', 'high',
                    f'{protocol} session cookie issued over cleartext transport', '', value,
                    key, context, {'cookie_name': key, 'direction': 'response'}))
        return findings

    @staticmethod
    def _finding(chunk: TCPChunk, protocol: str, category: str, severity: str, title: str,
                 username: str, secret: str, secret_type: str, evidence: str,
                 metadata: dict) -> Finding:
        return Finding(
            timestamp=chunk.timestamp,
            protocol=protocol,
            category=category,
            severity=severity,
            title=title,
            src=chunk.src,
            dst=chunk.dst,
            flow_id=chunk.flow.flow_id,
            username=username,
            secret=secret,
            secret_type=secret_type,
            evidence=evidence[:1000],
            metadata=metadata,
        )
