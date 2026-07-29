# Release checklist

## Code and tests

- [ ] Version updated in `pyproject.toml`, `setup.py`, package metadata, CLI banner, and changelog.
- [ ] `python3 -m compileall -q pcredz_ultimate` passes.
- [ ] `PYTHONPATH=. python3 -m unittest discover -s tests -v` passes.
- [ ] Offline install tested in a clean virtual environment.
- [ ] Optional live capture tested on a supported Linux host.
- [ ] No real PCAPs, credentials, tokens, cookies, hashes, customer names, or key logs are committed.
- [ ] Secret redaction remains the default.

## Documentation and provenance

- [ ] `CHANGELOG.md` contains user-visible changes.
- [ ] Protocol matrix and output schema are current.
- [ ] `NOTICE.md`, `UPSTREAM.md`, and GPLv3 license remain intact.
- [ ] Security limitations and authorization requirements are explicit.

## Git and release artifacts

- [ ] Working tree is clean.
- [ ] CI passes on all supported Python versions.
- [ ] Annotated version tag created and optionally signed.
- [ ] Source archives and Git bundle generated from the tag.
- [ ] SHA-256 checksums generated and verified.
- [ ] Release notes identify known limitations and migration impact.
