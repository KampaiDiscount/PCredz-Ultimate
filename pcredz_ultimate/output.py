from __future__ import annotations

import base64
import csv
import html
import json
import os
import re
import sqlite3
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, quote_plus

from .models import Finding


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
SENSITIVE_METADATA_RE = re.compile(
    r'(?i)(password|passwd|secret|token|credential|hashcat|hash_line|response|proof|ciphertext|mic|digest|session_key|message)'
)


def redact_secret(value: str) -> str:
    if not value:
        return ''
    if len(value) <= 4:
        return '*' * len(value)
    if len(value) <= 10:
        return value[:1] + '*' * (len(value) - 2) + value[-1:]
    return value[:3] + '*' * min(16, len(value) - 6) + value[-3:]


class AuditWriter:
    def __init__(self, output_dir: str, reveal_secrets: bool = False,
                 export_hashes: bool = False, write_html: bool = True,
                 verbose: bool = False):
        self.root = Path(output_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / 'logs').mkdir(exist_ok=True)
        (self.root / 'hashes').mkdir(exist_ok=True)
        for private_dir in (self.root, self.root / 'logs', self.root / 'hashes'):
            try:
                private_dir.chmod(0o700)
            except OSError:
                pass
        self.reveal_secrets = reveal_secrets
        self.export_hashes = export_hashes
        self.write_html = write_html
        self.verbose = verbose
        self.seen: set[str] = set()
        self.findings: list[Finding] = []
        self.counts = Counter()
        self.secret_reuse: dict[str, list[str]] = defaultdict(list)
        self._jsonl = (self.root / 'findings.jsonl').open('w', encoding='utf-8')
        self._csv_handle = (self.root / 'findings.csv').open('w', encoding='utf-8', newline='')
        self._csv = csv.DictWriter(self._csv_handle, fieldnames=[
            'finding_id', 'timestamp', 'severity', 'protocol', 'category', 'title',
            'src', 'dst', 'flow_id', 'username', 'secret_type', 'secret', 'evidence',
            'metadata_json', 'secret_fingerprint',
        ])
        self._csv.writeheader()
        self._db = sqlite3.connect(self.root / 'audit.sqlite')
        self._db.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                timestamp REAL,
                severity TEXT,
                protocol TEXT,
                category TEXT,
                title TEXT,
                src TEXT,
                dst TEXT,
                flow_id TEXT,
                username TEXT,
                secret_type TEXT,
                secret TEXT,
                evidence TEXT,
                metadata_json TEXT,
                secret_fingerprint TEXT
            )
        ''')
        self._db.commit()
        for private_file in (self.root / 'findings.jsonl', self.root / 'findings.csv', self.root / 'audit.sqlite'):
            try:
                private_file.chmod(0o600)
            except OSError:
                pass

    @staticmethod
    def _write_text_private(path: Path, text: str) -> None:
        path.write_text(text, encoding='utf-8')
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _display_secret(self, value: str) -> str:
        return value if self.reveal_secrets else redact_secret(value)

    def _sanitize_metadata(self, value: Any, key: str = '') -> Any:
        """Redact secret-bearing metadata unless explicit reveal was requested."""
        if self.reveal_secrets:
            return value
        if isinstance(value, dict):
            return {str(k): self._sanitize_metadata(v, str(k)) for k, v in value.items()}
        if isinstance(value, list):
            return [self._sanitize_metadata(v, key) for v in value]
        if isinstance(value, tuple):
            return [self._sanitize_metadata(v, key) for v in value]
        if isinstance(value, bytes):
            value = value.hex()
        if isinstance(value, str) and SENSITIVE_METADATA_RE.search(key):
            return redact_secret(value)
        return value

    def _sanitize_evidence(self, finding: Finding) -> str:
        evidence = finding.evidence or ''
        if self.reveal_secrets or not evidence:
            return evidence
        secret = finding.secret or ''
        replacements: set[str] = set()
        if secret:
            replacements.update({secret, quote(secret, safe=''), quote_plus(secret)})
            try:
                replacements.add(base64.b64encode(secret.encode()).decode())
            except Exception:
                pass
        for candidate in sorted((x for x in replacements if x), key=len, reverse=True):
            evidence = evidence.replace(candidate, redact_secret(candidate))
        # AUTH/Authorization evidence can hold a compound Base64 blob containing
        # both username and secret, so remove the blob even when it is not the
        # Base64 encoding of the secret alone.
        evidence = re.sub(
            r'(?i)((?:AUTH(?:ENTICATE)?\s+(?:PLAIN|LOGIN|XOAUTH2|OAUTHBEARER)|'
            r'Authorization:\s*(?:Basic|Bearer))\s+)[A-Za-z0-9._~+/=-]{8,}',
            r'\1<redacted-auth-material>', evidence,
        )
        return evidence

    def add(self, finding: Finding) -> bool:
        key = finding.stable_key()
        if key in self.seen and not self.verbose:
            return False
        self.seen.add(key)
        if not finding.finding_id:
            finding.finding_id = f'PCU-{len(self.findings) + 1:06d}'
        self.findings.append(finding)
        self.counts[finding.protocol] += 1
        self.counts[f'severity:{finding.severity.lower()}'] += 1
        self.counts[f'category:{finding.category.lower()}'] += 1
        fingerprint = finding.secret_fingerprint()
        if fingerprint:
            self.secret_reuse[fingerprint].append(finding.finding_id)

        row = finding.to_dict()
        row['secret'] = self._display_secret(finding.secret)
        row['metadata'] = self._sanitize_metadata(finding.metadata)
        row['evidence'] = self._sanitize_evidence(finding)
        row['timestamp_iso'] = datetime.fromtimestamp(finding.timestamp, timezone.utc).isoformat() if finding.timestamp else ''
        self._jsonl.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + '\n')
        self._jsonl.flush()

        csv_row = {
            'finding_id': finding.finding_id,
            'timestamp': row['timestamp_iso'],
            'severity': finding.severity,
            'protocol': finding.protocol,
            'category': finding.category,
            'title': finding.title,
            'src': str(finding.src),
            'dst': str(finding.dst),
            'flow_id': finding.flow_id,
            'username': finding.username,
            'secret_type': finding.secret_type,
            'secret': row['secret'],
            'evidence': row['evidence'],
            'metadata_json': json.dumps(row['metadata'], ensure_ascii=False, sort_keys=True),
            'secret_fingerprint': fingerprint,
        }
        self._csv.writerow(csv_row)
        self._csv_handle.flush()
        self._db.execute(
            'INSERT OR REPLACE INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
            (
                finding.finding_id, finding.timestamp, finding.severity, finding.protocol,
                finding.category, finding.title, str(finding.src), str(finding.dst),
                finding.flow_id, finding.username, finding.secret_type, row['secret'],
                row['evidence'], csv_row['metadata_json'], fingerprint,
            )
        )
        self._db.commit()

        self._write_protocol_log(finding, row['secret'], row['evidence'])
        self._write_hash_export(finding)
        self._print_console(finding, row['secret'])
        return True

    def _write_protocol_log(self, finding: Finding, secret: str, evidence: str) -> None:
        safe_protocol = ''.join(c if c.isalnum() or c in '-_' else '_' for c in finding.protocol)
        safe_category = ''.join(c if c.isalnum() or c in '-_' else '_' for c in finding.category)
        path = self.root / 'logs' / f'{safe_protocol}-{safe_category}.txt'
        with path.open('a', encoding='utf-8') as fh:
            ts = datetime.fromtimestamp(finding.timestamp, timezone.utc).isoformat() if finding.timestamp else ''
            parts = [ts, str(finding.src), '>', str(finding.dst), finding.title]
            if finding.username:
                parts.append(f'user={finding.username}')
            if secret:
                parts.append(f'{finding.secret_type or "secret"}={secret}')
            if evidence:
                parts.append(f'evidence={evidence}')
            fh.write(' | '.join(parts) + '\n')
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _write_hash_export(self, finding: Finding) -> None:
        if not self.export_hashes:
            return
        hash_line = finding.metadata.get('hashcat')
        hash_file = finding.metadata.get('hash_file')
        if not hash_line or not hash_file:
            return
        path = self.root / 'hashes' / str(hash_file)
        with path.open('a', encoding='utf-8') as fh:
            fh.write(str(hash_line) + '\n')
        try:
            path.chmod(0o600)
        except OSError:
            pass

    def _print_console(self, finding: Finding, secret: str) -> None:
        timestamp = datetime.fromtimestamp(finding.timestamp).strftime('%Y-%m-%d %H:%M:%S') if finding.timestamp else 'unknown-time'
        line = (
            f'[{timestamp}] [{finding.severity.upper():8}] [{finding.protocol}] '
            f'{finding.src} > {finding.dst} | {finding.title}'
        )
        if finding.username:
            line += f' | user={finding.username}'
        if secret:
            line += f' | {finding.secret_type or "secret"}={secret}'
        print(line)

    def finalize(self, inventory: dict[str, Any] | None = None,
                 capture_stats: dict[str, Any] | None = None) -> None:
        reuse_groups = [ids for ids in self.secret_reuse.values() if len(ids) > 1]
        findings_by_id = {finding.finding_id: finding for finding in self.findings}
        detailed_reuse = []
        for fingerprint, ids in self.secret_reuse.items():
            if len(ids) <= 1:
                continue
            group_findings = [findings_by_id[item] for item in ids if item in findings_by_id]
            detailed_reuse.append({
                'secret_fingerprint': fingerprint,
                'finding_ids': ids,
                'usernames': sorted({f.username for f in group_findings if f.username}),
                'protocols': sorted({f.protocol for f in group_findings}),
                'endpoints': sorted({f'{f.src}>{f.dst}' for f in group_findings}),
            })
        summary = {
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'finding_count': len(self.findings),
            'protocol_counts': dict(sorted((k, v) for k, v in self.counts.items() if not k.startswith('severity:'))),
            'category_counts': {
                key.split(':', 1)[1]: value
                for key, value in sorted(self.counts.items())
                if key.startswith('category:')
            },
            'severity_counts': {
                key.split(':', 1)[1]: value
                for key, value in sorted(self.counts.items())
                if key.startswith('severity:')
            },
            'secret_reuse_groups': reuse_groups,
            'secret_reuse_details': detailed_reuse,
            'capture_stats': capture_stats or {},
            'inventory': inventory or {},
            'secrets_revealed': self.reveal_secrets,
            'hashes_exported': self.export_hashes,
        }
        self._write_text_private(self.root / 'summary.json', json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))
        if inventory is not None:
            self._write_text_private(self.root / 'inventory.json', json.dumps(inventory, indent=2, ensure_ascii=False, sort_keys=True))
        if detailed_reuse:
            reuse_path = self.root / 'secret_reuse.csv'
            with reuse_path.open('w', encoding='utf-8', newline='') as fh:
                writer = csv.DictWriter(fh, fieldnames=['secret_fingerprint', 'finding_ids', 'usernames', 'protocols', 'endpoints'])
                writer.writeheader()
                for group in detailed_reuse:
                    writer.writerow({
                        'secret_fingerprint': group['secret_fingerprint'],
                        'finding_ids': ','.join(group['finding_ids']),
                        'usernames': ','.join(group['usernames']),
                        'protocols': ','.join(group['protocols']),
                        'endpoints': ','.join(group['endpoints']),
                    })
            try:
                reuse_path.chmod(0o600)
            except OSError:
                pass
        if self.write_html:
            self._write_html(summary)

        self._jsonl.close()
        self._csv_handle.close()
        self._db.close()

    def _write_html(self, summary: dict[str, Any]) -> None:
        rows = []
        for finding in sorted(self.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity.lower(), 99), f.timestamp)):
            secret = self._display_secret(finding.secret)
            rows.append(
                '<tr>'
                f'<td>{html.escape(finding.finding_id)}</td>'
                f'<td>{html.escape(finding.severity)}</td>'
                f'<td>{html.escape(finding.protocol)}</td>'
                f'<td>{html.escape(finding.title)}</td>'
                f'<td>{html.escape(str(finding.src))}</td>'
                f'<td>{html.escape(str(finding.dst))}</td>'
                f'<td>{html.escape(finding.username)}</td>'
                f'<td>{html.escape(secret)}</td>'
                f'<td><code>{html.escape(self._sanitize_evidence(finding))}</code></td>'
                '</tr>'
            )
        report = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>PCredz Ultimate Audit</title>
<style>
body{{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:2rem;color:#202124}}
h1,h2{{margin-bottom:.4rem}} .summary{{display:flex;gap:1rem;flex-wrap:wrap}}
.card{{border:1px solid #ddd;border-radius:8px;padding:1rem;min-width:160px}}
table{{border-collapse:collapse;width:100%;font-size:13px}} th,td{{border:1px solid #ddd;padding:.45rem;vertical-align:top}}
th{{background:#f5f5f5;position:sticky;top:0}} code{{white-space:pre-wrap;word-break:break-all}}
</style></head><body>
<h1>PCredz Ultimate Network Credential Audit</h1>
<p>Generated {html.escape(summary['generated_at'])}. Secrets are {'shown' if self.reveal_secrets else 'redacted'}.</p>
<div class="summary"><div class="card"><strong>Findings</strong><br>{len(self.findings)}</div>
<div class="card"><strong>Reuse groups</strong><br>{len(summary['secret_reuse_groups'])}</div>
<div class="card"><strong>Protocols</strong><br>{len(summary['protocol_counts'])}</div></div>
<h2>Findings</h2>
<table><thead><tr><th>ID</th><th>Severity</th><th>Protocol</th><th>Title</th><th>Source</th><th>Destination</th><th>Username</th><th>Secret</th><th>Evidence</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></body></html>'''
        self._write_text_private(self.root / 'report.html', report)
