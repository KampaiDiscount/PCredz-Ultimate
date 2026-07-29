# PCredz Ultimate 3.1.0

PCredz Ultimate 3.1.0 is the first packaged snapshot of the rewritten passive credential and authentication-material auditing engine.

## Highlights

- Sequence-aware TCP stream reconstruction instead of packet-local credential regex scanning.
- Structured HTTP parsing for URL-encoded, JSON, multipart, XML, authentication headers, cookies and tokens.
- Context-aware identity resolution for dynamically generated registration fields.
- Protocol-aware extraction across cleartext authentication, NTLM, selected Kerberos and challenge-response traffic.
- PCAP and PCAPNG support with expanded link-layer handling.
- Redaction by default with explicit secret-reveal and hash-export controls.
- JSONL, CSV, SQLite, protocol logs, inventory data and HTML reporting.
- Nineteen automated regression tests covering capture parsing, detectors, output redaction and end-to-end reassembly.

## Known limitations

- Encrypted TLS, SSH, IPsec and protected Wi-Fi payloads are not decrypted without separate key material and decryption support.
- Optional live capture depends on `pcapy-ng` and system libpcap development headers.
- The codebase has diverged substantially from upstream PCredz; upstream fixes should be reviewed and ported selectively.

## Provenance

This is a modified GPLv3-compatible derivative inspired by PCredz 2.1.0. It is not an official upstream release. See `NOTICE.md` and `UPSTREAM.md`.
