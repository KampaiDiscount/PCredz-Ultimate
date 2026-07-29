from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from pcredz_ultimate.models import Endpoint, Finding
from pcredz_ultimate.output import AuditWriter


class OutputTests(unittest.TestCase):
    def test_nested_sensitive_metadata_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            writer = AuditWriter(td)
            writer.add(Finding(
                timestamp=1.0,
                protocol='TEST',
                category='challenge_response',
                severity='medium',
                title='test',
                src=Endpoint('192.0.2.1', 1),
                dst=Endpoint('192.0.2.2', 2),
                secret='raw-secret-value',
                secret_type='hash',
                metadata={
                    'hashcat': 'user:raw-secret-value',
                    'nested': {'response': 'raw-secret-value'},
                    'challenge': 'public-challenge',
                },
            ))
            writer.finalize()
            text = (Path(td) / 'findings.jsonl').read_text()
            self.assertNotIn('raw-secret-value', text)
            row = json.loads(text)
            self.assertEqual(row['metadata']['challenge'], 'public-challenge')

    def test_compound_auth_evidence_is_redacted(self) -> None:
        import base64
        blob = base64.b64encode(b"\x00alice\x00mailpass").decode()
        with tempfile.TemporaryDirectory() as td:
            writer = AuditWriter(td)
            writer.add(Finding(
                timestamp=1.0, protocol='SMTP', category='cleartext_credential',
                severity='high', title='SMTP SASL PLAIN exposed',
                src=Endpoint('192.0.2.1', 50000), dst=Endpoint('192.0.2.2', 25),
                username='alice', secret='mailpass', secret_type='password',
                evidence=f'AUTH PLAIN {blob}',
            ))
            writer.finalize()
            combined = ''.join(path.read_text(errors='ignore') for path in Path(td).rglob('*') if path.is_file() and path.suffix != '.sqlite')
            self.assertNotIn(blob, combined)
            self.assertNotIn('mailpass', combined)


if __name__ == '__main__':
    unittest.main()
