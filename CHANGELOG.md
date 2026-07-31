# Changelog

## 3.1.1

- Fixed `./install.sh --live` on Kali, Debian, and Ubuntu by detecting and installing the required compiler, Python development headers, virtual-environment support, `pkg-config`, and `libpcap-dev` before building `pcapy-ng`.
- Added explicit checks for `pcap.h` and `Python.h`, followed by a real `pcapy` import and capture-interface discovery validation.
- Added a `--no-system-packages` mode and clearer guidance for non-apt distributions.
- Added CI coverage for the exact live installer path on Python 3.13, and constrained the optional backend to `pcapy-ng>=2.0.0,<3`.
- Improved the runtime error shown when live capture is requested without a working backend.
- Added support for common compact HTTP password fields such as `passw` and `pw`; this includes the Altoro Mutual/Testfire `uid` + `passw` login form.
- Prevented the generic line-auth detector from misclassifying HTTP/TLS flows as Telnet when page content contains text such as `Password:`.

## 3.1.0

- Added context-aware HTTP identity resolution: explicit login identifiers remain preferred, while registration forms now combine first/given and last/family names before falling back to email.
- Added regression coverage for dynamically suffixed fields such as `first_name-65467`, `last_name-65467`, `user_email-65467`, and `user_password-65467`.
- Updated the research basis and operator documentation.

## 3.0.0

- Replaced packet-local regex scanning with sequence-aware TCP reassembly and application framing.
- Added native PCAP/PCAPNG and expanded link-layer support.
- Added structured HTTP body parsing with dynamic form-field detection and response-noise suppression.
- Added stateful cleartext and challenge-response parsers for web, mail, directory, database, IoT, proxy and AAA protocols.
- Added TLS/DNS/DHCP/EAPOL inventory and host correlation.
- Added redaction-by-default, fingerprint-based reuse analysis, optional hash export, SQLite, JSONL, CSV and HTML outputs.
- Added explicit authorization acknowledgement for live capture.
