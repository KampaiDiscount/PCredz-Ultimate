#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="${PCREDZ_VENV:-$ROOT/.venv}"
PYTHON="${PCREDZ_PYTHON:-python3}"
LIVE=0
AUTO_SYSTEM_PACKAGES=1

usage() {
    cat <<'USAGE'
Usage: ./install.sh [OPTIONS]

Install the local PCredz Ultimate launcher into .venv.

Options:
  --live                 Install and validate optional live-capture support.
                         On Kali/Debian/Ubuntu, missing native prerequisites
                         are installed automatically with apt-get.
  --no-system-packages   Never invoke apt-get or sudo. Fail with an actionable
                         package list when native prerequisites are missing.
  -h, --help             Show this help text.

Environment:
  PCREDZ_VENV             Override the virtual-environment path.
  PCREDZ_PYTHON           Override the Python interpreter (default: python3).
USAGE
}

info()    { printf '[*] %s\n' "$*"; }
success() { printf '[+] %s\n' "$*"; }
warn()    { printf '[!] %s\n' "$*" >&2; }
die()     { printf '[error] %s\n' "$*" >&2; exit 1; }
have()    { command -v "$1" >/dev/null 2>&1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --live)
            LIVE=1
            ;;
        --no-system-packages)
            AUTO_SYSTEM_PACKAGES=0
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "Unknown option: $1"
            ;;
    esac
    shift
done

have "$PYTHON" || die "Python interpreter not found: $PYTHON"

"$PYTHON" - <<'PY'
import sys
if sys.version_info < (3, 10):
    raise SystemExit("Python 3.10 or newer is required")
PY

run_as_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        "$@"
    elif have sudo; then
        sudo "$@"
    else
        die "Root privileges are required to install system packages. Re-run with sudo or install the prerequisites manually."
    fi
}

run_apt() {
    local attempt
    local max_attempts=4

    for ((attempt = 1; attempt <= max_attempts; attempt++)); do
        if run_as_root env DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=120 "$@"; then
            return 0
        fi
        if ((attempt < max_attempts)); then
            warn "apt-get failed (attempt $attempt/$max_attempts); retrying in 5 seconds."
            sleep 5
        fi
    done

    die "apt-get failed after $max_attempts attempts. Resolve the package-manager or network error and retry."
}

install_debian_packages() {
    local packages=("$@")
    [[ ${#packages[@]} -gt 0 ]] || return 0

    if [[ "$AUTO_SYSTEM_PACKAGES" -ne 1 ]]; then
        warn "Missing native prerequisite(s): ${packages[*]}"
        warn "On Kali/Debian/Ubuntu, install them with:"
        warn "  sudo apt-get update"
        warn "  sudo apt-get install -y ${packages[*]}"
        exit 1
    fi

    have apt-get || {
        warn "Missing native prerequisite(s): ${packages[*]}"
        die "Automatic installation is supported on apt-based systems. Install the equivalent compiler, Python, pkg-config, and libpcap development packages for this operating system."
    }

    info "Installing missing native prerequisite(s): ${packages[*]}"
    run_apt update
    run_apt install -y --no-install-recommends "${packages[@]}"
}

create_venv() {
    if [[ -x "$VENV/bin/python" ]]; then
        info "Reusing virtual environment: $VENV"
        return 0
    fi

    info "Creating virtual environment: $VENV"
    if "$PYTHON" -m venv "$VENV"; then
        return 0
    fi

    warn "Python could not create the virtual environment."
    if have apt-get && [[ "$AUTO_SYSTEM_PACKAGES" -eq 1 ]]; then
        install_debian_packages python3-venv
        "$PYTHON" -m venv "$VENV" || die "Virtual-environment creation still failed after installing python3-venv."
        return 0
    fi

    die "Install the venv module for your Python interpreter (Kali/Debian/Ubuntu: sudo apt-get install -y python3-venv), then retry."
}

python_headers_present() {
    "$VENV/bin/python" - <<'PY' >/dev/null 2>&1
import os
import sysconfig
include = sysconfig.get_paths().get("include", "")
raise SystemExit(0 if include and os.path.isfile(os.path.join(include, "Python.h")) else 1)
PY
}

pcap_headers_present() {
    local cxx="${CXX:-g++}"
    have "$cxx" || return 1
    printf '#include <pcap.h>\n' | "$cxx" -x c++ -E - >/dev/null 2>&1
}

prepare_live_prerequisites() {
    local packages=()

    have "${CXX:-g++}" || packages+=(build-essential)
    have pkg-config || packages+=(pkg-config)
    python_headers_present || packages+=(python3-dev)
    pcap_headers_present || packages+=(libpcap-dev)

    if [[ ${#packages[@]} -gt 0 ]]; then
        local unique=()
        local package existing seen
        for package in "${packages[@]}"; do
            seen=0
            for existing in "${unique[@]:-}"; do
                if [[ "$existing" == "$package" ]]; then
                    seen=1
                    break
                fi
            done
            [[ "$seen" -eq 1 ]] || unique+=("$package")
        done
        install_debian_packages "${unique[@]}"
    fi

    have "${CXX:-g++}" || die "A C++ compiler is required to build pcapy-ng."
    have pkg-config || die "pkg-config is required for live-capture dependency builds."
    python_headers_present || die "Python development headers are missing (Python.h was not found)."
    pcap_headers_present || die "libpcap development headers are missing (pcap.h was not found)."
}

create_venv

cat > "$VENV/bin/pcredz" <<EOF_LAUNCHER
#!/usr/bin/env bash
export PYTHONPATH="$ROOT\${PYTHONPATH:+:\$PYTHONPATH}"
exec "$VENV/bin/python" "$ROOT/Pcredz" "\$@"
EOF_LAUNCHER
chmod +x "$VENV/bin/pcredz"
ln -sf pcredz "$VENV/bin/pcredz-ultimate"

if [[ "$LIVE" -eq 1 ]]; then
    info "Preparing optional live-capture support."
    prepare_live_prerequisites

    info "Installing pcapy-ng inside the virtual environment."
    "$VENV/bin/python" -m pip install --upgrade pip setuptools wheel
    "$VENV/bin/python" -m pip install --no-cache-dir -r "$ROOT/requirements-live.txt"

    "$VENV/bin/python" - <<'PY'
import pcapy

interfaces = sorted(set(pcapy.findalldevs()))
print(f"[+] pcapy-ng loaded from: {pcapy.__file__}")
if interfaces:
    print("[+] Capture interfaces visible: " + ", ".join(interfaces))
else:
    print("[!] pcapy-ng loaded, but no capture interfaces were returned.")
PY
fi

success "Installed launcher in: $VENV/bin/pcredz"
printf '%s\n' \
    "[+] Offline example:" \
    "    $VENV/bin/pcredz -f capture.pcap -o audit" \
    "[+] Reveal disposable test secrets explicitly:" \
    "    $VENV/bin/pcredz -f capture.pcap -o audit --reveal-secrets"

if [[ "$LIVE" -eq 1 ]]; then
    printf '%s\n' \
        "[+] Authorized live-capture example:" \
        "    sudo $VENV/bin/pcredz -i eth0 --live-authorized -o live-audit"
fi
