# Contributing

PCredz Ultimate is intended for authorized passive network-security auditing. Contributions should preserve that scope.

## Development setup

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e .
PYTHONPATH=. .venv/bin/python -m unittest discover -s tests -v
```

The offline parser must remain usable without third-party dependencies. Live capture is optional and may be installed with:

```bash
.venv/bin/python -m pip install -e '.[live]'
```

On Debian-derived systems, compiling `pcapy-ng` normally requires `build-essential`, `python3-dev`, and `libpcap-dev`.

## Branches and commits

- Keep `main` releasable.
- Develop changes in a topic branch such as `fix/http-framing` or `feat/protocol-name`.
- Add regression coverage for parser and detector changes.
- Do not commit real captures, customer data, recovered credentials, hashes, tokens, cookies, TLS key logs, or audit output.
- Use conventional, imperative commit subjects where practical.

## Pull requests

Describe the protocol behavior, test evidence, false-positive implications, security/privacy impact, and any output-schema changes. New credential detectors must include both positive and negative fixtures.

## Licensing and provenance

The project is distributed under GPLv3-or-later. Preserve `LICENSE`, `NOTICE.md`, upstream attribution, and prominent modification notices.
