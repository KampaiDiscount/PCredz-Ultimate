# PCredz Ultimate 3.1.1

PCredz Ultimate is a passive credential, token, challenge-response and network-exposure auditing tool for authorized PCAP/PCAPNG files and explicitly authorized live captures.

It was built to solve the two failure modes seen in packet-by-packet credential scanners:

- missed credentials when an application request spans multiple TCP segments;
- noisy false positives caused by applying broad password regexes to compressed or binary server responses.

The offline parser has no third-party dependencies. It reads PCAP and PCAPNG directly, reconstructs TCP streams, applies stateful protocol parsers, and generates JSONL, CSV, SQLite, protocol logs, inventory data and an HTML report.

## Quick start

```bash
./install.sh
.venv/bin/pcredz -f capture.pcap -o audit
```

By default, secrets are redacted:

```text
[HIGH] [HTTP] 192.0.2.10:53219 > 198.51.100.20:80 |
HTTP credential field exposed | user=test@example.test |
user_password-65467=P@s*****123
```

For controlled testing with disposable credentials:

```bash
.venv/bin/pcredz -f capture.pcap -o audit \
  --reveal-secrets --export-hashes
```

Process a capture directory:

```bash
.venv/bin/pcredz -d /evidence/pcaps -o audit
```

Live capture is separately gated:

```bash
./install.sh --live
sudo .venv/bin/pcredz -i eth0 --live-authorized -o live-audit
```

On Kali, Debian, and Ubuntu, `./install.sh --live` detects and installs missing native prerequisites (`build-essential`, `python3-dev`, `python3-venv`, `pkg-config`, and `libpcap-dev`) before compiling `pcapy-ng` inside `.venv`. Kali's externally managed system Python is not modified. Use `./install.sh --live --no-system-packages` when system package changes must be handled separately. On other distributions, install the equivalent compiler, Python headers, and libpcap development package first.

HTTP form matching is field-name aware and includes common compact aliases such as `uid`, `passw`, `pw`, `pwd`, `passwd`, and `password`. The generic line-oriented protocol detector is isolated from HTTP/TLS flows to prevent HTML labels from generating Telnet false positives.

## Why the ButterflySA form is detected cleanly

A dynamically named URL-encoded field such as:

```text
first_name-65467=Alex&last_name-65467=Example&user_email-65467=alex%40example.test&user_password-65467=P%40ssw0rd123
```

is found only after the complete HTTP request has been reassembled and parsed. The field name is classified structurally, the value is URL-decoded, the matching confirmation field is suppressed, and unrelated compressed HTTP response bodies are not searched as arbitrary text. Identity resolution prefers an explicit login/username; when a registration form has no such field, it combines the given and family names (`Alex Example`) before falling back to email.

## Principal capabilities

- Pure-Python PCAP and PCAPNG parsing, including multi-interface PCAPNG metadata.
- Ethernet, VLAN/QinQ, Linux SLL/SLL2, raw IP, loopback, and unprotected radiotap/802.11 data frames.
- IPv4 and IPv6 TCP/UDP parsing.
- Sequence-aware TCP reassembly with retransmission and overlap suppression.
- Cleartext credential extraction, bearer/API/session-token exposure, NTLM and selected Kerberos/challenge-response material.
- Stateful STARTTLS/SSL-upgrade tracking.
- Host, DNS, DHCP, HTTP, User-Agent and TLS ClientHello inventory.
- Redaction by default, SHA-256 secret fingerprints, reuse grouping, and optional explicit hash exports.

See `docs/PROTOCOL_MATRIX.md` for the protocol matrix and limitations.

## Important options

```text
-f, --file FILE          Read a PCAP/PCAPNG; repeat for multiple files
-d, --directory DIR      Recursively process capture files
-i, --interface IFACE    Passive live capture
-o, --output DIR         Output directory
--overwrite-output       Recreate a non-empty output directory
--reveal-secrets         Store/show full values instead of redaction
--export-hashes          Export supported challenge-response lines
--disable NAME[,NAME]    Disable detector, protocol, or category
--exclude-host IP/CIDR   Exclude unrelated hosts or networks
--live-authorized        Required acknowledgement for live capture
-v, --verbose            Diagnostics and retain duplicate findings
```

## Validate the build

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 -m compileall -q pcredz_ultimate
```

## Scope and ethics

This utility is passive. It does not perform MITM, downgrade, replay, credential validation, password cracking or traffic injection. Use only on systems and networks you are authorized to assess. See `SECURITY.md` for evidence-handling guidance.

## License and attribution

GPLv3 or later. This is an independently modified/reimplemented derivative inspired by PCredz 2.1.0, created by Laurent Gaffié. It is not an official upstream PCredz release. See `NOTICE.md` and `LICENSE`.

## Repository workflow

This source tree is prepared for Git-based development with CI, release hygiene, upstream provenance, and capture-data exclusions. See `docs/FORKING_AND_PUBLISHING.md`, `CONTRIBUTING.md`, `UPSTREAM.md`, and `RELEASE_CHECKLIST.md`.
