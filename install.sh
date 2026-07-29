#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PCREDZ_VENV:-$ROOT/.venv}"
LIVE=0
[[ "${1:-}" == "--live" ]] && LIVE=1

python3 - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
PY

python3 -m venv "$VENV"
cat > "$VENV/bin/pcredz" <<EOF
#!/usr/bin/env bash
export PYTHONPATH="$ROOT\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$VENV/bin/python" "$ROOT/Pcredz" "\$@"
EOF
chmod +x "$VENV/bin/pcredz"
ln -sf pcredz "$VENV/bin/pcredz-ultimate"

if [[ "$LIVE" -eq 1 ]]; then
    echo "[*] Installing optional live-capture dependency."
    echo "[*] libpcap development headers must already be installed (for example: libpcap-dev)."
    "$VENV/bin/python" -m pip install pcapy-ng
fi

cat <<EOF
[+] Installed launcher in: $VENV/bin/pcredz
[+] Offline example:
    $VENV/bin/pcredz -f capture.pcap -o audit
[+] Reveal disposable test secrets explicitly:
    $VENV/bin/pcredz -f capture.pcap -o audit --reveal-secrets
EOF
