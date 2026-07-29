# Safe-use and data-handling model

PCredz Ultimate is a **passive** auditing and network-forensics utility. It does not perform interception, downgrade, replay, credential validation, password cracking, or active network manipulation.

Use it only on captures and interfaces you are authorized to assess. Live capture requires the explicit `--live-authorized` acknowledgement.

Recovered credentials and authentication material are sensitive. By default, console and stored outputs redact secret values while retaining a SHA-256 fingerprint for deduplication and reuse analysis. Full values require `--reveal-secrets`; supported hash exports require the separate `--export-hashes` option. Store output on encrypted media, restrict permissions, and destroy it according to the engagement data-retention plan.

TLS, SSH, IPsec, WPA/WPA2 protected payloads, and other encrypted application traffic are not decrypted. Metadata may still be inventoried where visible.
