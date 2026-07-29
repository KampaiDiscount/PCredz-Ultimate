# Validation record — PCredz Ultimate 3.1.0

The release was syntax-checked and exercised with the bundled standard-library test suite.

```bash
PYTHONPATH=. python3 -m unittest discover -s tests -v
python3 -m compileall -q pcredz_ultimate
```

Result at packaging time: **19 tests passed**.

The regression suite covers:

- segmented HTTP registration bodies and retransmission/noise suppression;
- dynamic credential field suffixes such as `user_password-65467`;
- identity resolution from first/given plus last/family name before email fallback;
- explicit username precedence for ordinary login forms;
- HTTP Basic/form redaction and explicit secret reveal behavior;
- repeated `Set-Cookie` parsing;
- SMTP SASL PLAIN, SOCKS5 username/password, AMQP SASL PLAIN;
- Memcached SASL, MQTT CONNECT, Redis AUTH;
- LDAP Simple Bind and SNMPv1/v2c community strings;
- MSSQL LOGIN7 password de-obfuscation;
- TLS 1.3 ServerHello version handling;
- nested metadata and compound authentication evidence redaction;
- little-endian PCAPNG parsing.

A clean virtual-environment smoke test was also performed:

```bash
PCREDZ_VENV=/tmp/pcu-venv ./install.sh
/tmp/pcu-venv/bin/pcredz \
  -f examples/demo-segmented-http.pcap \
  -o /tmp/pcu-smoke \
  --overwrite-output \
  --reveal-secrets
```

Expected identity output from the bundled dynamic registration capture:

```text
user=mpo popz poppers | user_password-65467=Disposable-Test-Only!
```

Limitations are documented in `docs/PROTOCOL_MATRIX.md` and `README.md`. In particular, protected traffic is not decrypted, and IP fragment reassembly is not implemented.
