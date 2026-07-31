# PCredz Ultimate 3.1.1

PCredz Ultimate 3.1.1 is a live-capture reliability and HTTP detector precision release.

## Fixed

- `./install.sh --live` now detects and installs the native build prerequisites required by `pcapy-ng` on Kali, Debian, and Ubuntu:
  - `build-essential`
  - `python3-dev`
  - `python3-venv`
  - `pkg-config`
  - `libpcap-dev`
- The installer checks that the compiler can resolve `pcap.h` and that the selected Python interpreter has `Python.h` before starting the wheel build.
- `pcapy-ng` is installed only inside PCredz Ultimate's virtual environment, preserving Kali's externally managed system Python.
- Installation concludes with a real `pcapy` import and capture-interface discovery check.
- A new `--no-system-packages` option supports operators who manage native dependencies separately.
- The runtime error for a missing live backend now directs operators to `./install.sh --live` and names the required components.
- HTTP form extraction now recognizes compact password field names including `passw` and `pw`, while retaining context-aware username resolution such as `uid`.
- HTTP/TLS flows are excluded from the generic line-auth heuristic, eliminating false Telnet findings such as treating `GET /images/logo.gif HTTP/1.1` as a password after an HTML `Password:` label.

## Packaging and CI

- Package version updated to `3.1.1`.
- Optional live backend constrained to `pcapy-ng>=2.0.0,<3`.
- GitHub Actions now validates shell syntax and exercises the exact live installer path on Python 3.13 with libpcap headers installed.

## Upgrade

From an existing checkout:

```bash
git pull --ff-only origin master
./install.sh --live
sudo .venv/bin/pcredz -i eth0 --live-authorized -o live-audit
```

No capture format or report schema changed in this release. HTTP detector coverage and line-auth precision were improved.
