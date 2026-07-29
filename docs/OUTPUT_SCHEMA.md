# Output structure

- `report.html` — severity-sorted review report.
- `summary.json` — counts, capture statistics, secret-reuse groups and inventory summary.
- `inventory.json` — host/IP/MAC/hostname, DNS, HTTP Host, User-Agent, TLS SNI and interface inventory.
- `findings.jsonl` — one structured finding per line.
- `findings.csv` — analyst-friendly flat export.
- `audit.sqlite` — queryable findings database.
- `logs/` — protocol/category text logs.
- `hashes/` — created only when supported material is exported with `--export-hashes`.

Secrets are redacted by default in every output, including nested metadata. `secret_fingerprint` is a SHA-256 digest used to identify repeated values without storing the value itself. `--reveal-secrets` changes this behavior and must be used only with disposable test accounts or under the assessment evidence-handling plan.
