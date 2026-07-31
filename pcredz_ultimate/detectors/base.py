from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Iterator
from urllib.parse import parse_qsl, unquote_plus

from ..models import Finding, TCPChunk, UDPDatagram


SECRET_KEY_RE = re.compile(
    r'(?i)(?:^|[_\-.])('
    r'password|passwd|passw|pass|passcode|passphrase|pwd|pw|pin|otp|totp|mfa[_-]?(?:code|token)|'
    r'one[_-]?time[_-]?(?:password|passcode|code)|verification[_-]?code|security[_-]?answer|'
    r'secret|client[_-]?secret|'
    r'api[_-]?key|access[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|'
    r'auth[_-]?token|session[_-]?(?:id|token)|bearer|jwt|private[_-]?token|'
    r'authorization|credential'
    r')(?:$|[_\-.\d])'
)
USER_KEY_RE = re.compile(
    r'(?i)(?:^|[_\-.])('
    r'user(?:name)?|login|email|mail|account|userid|user[_-]?id|identifier|authcid'
    r')(?:$|[_\-.\d])'
)

# Identity fields need more nuance than a single broad `user|email` regex.
# Registration forms frequently have first/last-name fields plus an email address,
# while login forms usually have an explicit username/login identifier.  Prefer an
# explicit authentication identifier, otherwise combine the human name, and only
# then fall back to an email address.
EXPLICIT_USER_FIELD_RE = re.compile(
    r'(?i)^(?:user(?:name)?|user[_-]?id|userid|login(?:[_-]?(?:id|name|user))?|'
    r'account(?:[_-]?(?:id|name))?|identifier|authcid|member(?:[_-]?name)?|uid|uname)$'
)
EMAIL_FIELD_RE = re.compile(r'(?i)^(?:user[_-]?)?(?:e[_-]?)?mail(?:[_-]?address)?$')
FIRST_NAME_FIELD_RE = re.compile(r'(?i)^(?:first[_-]?name|firstname|given[_-]?name|givenname|forename)$')
LAST_NAME_FIELD_RE = re.compile(r'(?i)^(?:last[_-]?name|lastname|family[_-]?name|familyname|surname)$')
FULL_NAME_FIELD_RE = re.compile(r'(?i)^(?:full[_-]?name|fullname|display[_-]?name|displayname|name)$')
DYNAMIC_NUMERIC_SUFFIX_RE = re.compile(r'(?:[_\-.]?\d+)$')
CONFIRM_KEY_RE = re.compile(r'(?i)(confirm|confirmation|repeat|verify|verification|again)')
JWT_RE = re.compile(r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{0,}\b')
AWS_ACCESS_KEY_RE = re.compile(r'\b(?:AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b')
GENERIC_BEARER_RE = re.compile(r'(?i)\bBearer\s+([A-Za-z0-9._~+\-/]+=*)')


class Detector:
    name = 'detector'

    def on_tcp(self, chunk: TCPChunk) -> Iterable[Finding]:
        return ()

    def on_udp(self, datagram: UDPDatagram) -> Iterable[Finding]:
        return ()

    def on_l2(self, packet: Any) -> Iterable[Finding]:
        return ()

    def finalize(self) -> Iterable[Finding]:
        return ()


def safe_decode(data: bytes, encoding: str = 'utf-8') -> str:
    return data.decode(encoding, errors='replace')


def printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    printable = sum(b in (9, 10, 13) or 32 <= b <= 126 for b in data)
    return printable / len(data)


def decode_base64_loose(value: str | bytes) -> bytes | None:
    if isinstance(value, str):
        raw = value.strip().encode('ascii', errors='ignore')
    else:
        raw = value.strip()
    if not raw or len(raw) > 16384:
        return None
    raw += b'=' * ((4 - len(raw) % 4) % 4)
    try:
        return base64.b64decode(raw, validate=False)
    except (binascii.Error, ValueError):
        return None


def parse_sasl_plain(decoded: bytes) -> tuple[str, str, str] | None:
    parts = decoded.split(b'\x00')
    if len(parts) < 3:
        return None
    authzid = parts[-3].decode('utf-8', errors='replace')
    authcid = parts[-2].decode('utf-8', errors='replace')
    password = parts[-1].decode('utf-8', errors='replace')
    if not authcid or not password:
        return None
    return authzid, authcid, password


def looks_like_secret(value: str) -> bool:
    value = value.strip()
    if not value or len(value) > 8192:
        return False
    if value.lower() in {'null', 'none', 'undefined', 'true', 'false', 'yes', 'no', '0', '1'}:
        return False
    return any(not ch.isspace() for ch in value)


def flatten_json(value: Any, prefix: str = '') -> Iterator[tuple[str, str]]:
    if isinstance(value, dict):
        for key, item in value.items():
            child = f'{prefix}.{key}' if prefix else str(key)
            yield from flatten_json(item, child)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child = f'{prefix}[{index}]'
            yield from flatten_json(item, child)
    elif value is not None:
        yield prefix, str(value)


def _identity_field_name(key: str) -> str:
    """Return a normalized terminal field name for identity inference.

    Examples:
      profile.first_name-65467 -> first_name
      user[email]              -> user_email
      form.login-id            -> login_id
    """
    value = unquote_plus(str(key)).strip().lower()
    value = re.sub(r'\[(?:\d+|[^\]]+)\]', lambda m: '_' + m.group(0)[1:-1], value)
    value = value.rsplit('.', 1)[-1]
    value = re.sub(r'[^a-z0-9]+', '_', value).strip('_')
    value = DYNAMIC_NUMERIC_SUFFIX_RE.sub('', value).strip('_')
    return value


def infer_structured_identity(items: Iterable[tuple[str, str]]) -> str:
    """Infer the most useful identity associated with structured credentials.

    Precedence:
      1. explicit username/login/account identifier;
      2. combined first + last name;
      3. full/display name;
      4. email address;
      5. legacy broad username-field fallback.
    """
    pairs = [(str(k), unquote_plus(str(v)).strip()) for k, v in items]
    explicit: list[str] = []
    emails: list[str] = []
    first_names: list[str] = []
    last_names: list[str] = []
    full_names: list[str] = []
    legacy: list[str] = []

    for key, value in pairs:
        if not looks_like_secret(value):
            continue
        field = _identity_field_name(key)
        if EXPLICIT_USER_FIELD_RE.fullmatch(field):
            explicit.append(value)
        elif FIRST_NAME_FIELD_RE.fullmatch(field):
            first_names.append(value)
        elif LAST_NAME_FIELD_RE.fullmatch(field):
            last_names.append(value)
        elif FULL_NAME_FIELD_RE.fullmatch(field):
            full_names.append(value)
        elif EMAIL_FIELD_RE.fullmatch(field):
            emails.append(value)
        elif USER_KEY_RE.search(key):
            legacy.append(value)

    if explicit:
        return explicit[0]
    if first_names and last_names:
        return f'{first_names[0]} {last_names[0]}'.strip()
    if full_names:
        return full_names[0]
    if first_names:
        return first_names[0]
    if last_names:
        return last_names[0]
    if emails:
        return emails[0]
    return legacy[0] if legacy else ''


def extract_structured_credentials(items: Iterable[tuple[str, str]]) -> list[tuple[str, str, str]]:
    pairs = [(str(k), str(v)) for k, v in items]
    username = infer_structured_identity(pairs)
    findings: list[tuple[str, str, str]] = []
    seen_values: set[str] = set()
    for key, value in pairs:
        if not SECRET_KEY_RE.search(key) or CONFIRM_KEY_RE.search(key):
            continue
        decoded = unquote_plus(value)
        if not looks_like_secret(decoded):
            continue
        if decoded in seen_values:
            continue
        seen_values.add(decoded)
        findings.append((key, username, decoded))
    return findings


def parse_http_digest(value: str) -> dict[str, str]:
    value = value.strip()
    if value.lower().startswith('digest '):
        value = value[7:]
    result: dict[str, str] = {}
    token = ''
    in_quotes = False
    escaped = False
    parts: list[str] = []
    for ch in value:
        if escaped:
            token += ch
            escaped = False
            continue
        if ch == '\\' and in_quotes:
            escaped = True
            token += ch
            continue
        if ch == '"':
            in_quotes = not in_quotes
            token += ch
            continue
        if ch == ',' and not in_quotes:
            parts.append(token.strip())
            token = ''
        else:
            token += ch
    if token.strip():
        parts.append(token.strip())
    for part in parts:
        if '=' not in part:
            continue
        key, val = part.split('=', 1)
        val = val.strip().strip('"')
        result[key.strip().lower()] = val
    return result


def parse_multipart(body: bytes, boundary: str) -> list[tuple[str, str]]:
    boundary_bytes = ('--' + boundary).encode('utf-8', errors='ignore')
    results: list[tuple[str, str]] = []
    for part in body.split(boundary_bytes):
        part = part.strip(b'\r\n-')
        if not part or b'\r\n\r\n' not in part:
            continue
        raw_headers, value = part.split(b'\r\n\r\n', 1)
        headers = safe_decode(raw_headers)
        name_match = re.search(r'(?i)content-disposition:\s*form-data;[^\r\n]*\bname="([^"]+)"', headers)
        if not name_match:
            continue
        if re.search(r'(?i)\bfilename="', headers):
            continue
        text = safe_decode(value.rstrip(b'\r\n'))
        results.append((name_match.group(1), text))
    return results
