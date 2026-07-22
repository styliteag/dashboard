#!/bin/sh
# install-linux.sh — Install the orbit agent on a generic Linux server (§25).
#
# Deliberately separate from install.sh (FreeBSD): the firewall installer is
# outside the self-update path and stays untouched — zero regression risk for
# the fleet. This one installs the same orbit_agent.py + run-agent.sh
# supervisor, plus the vendored Checkmk agent that does the data collection
# on Linux (DR-10), and a systemd unit that starts the supervisor.
#
# Usage (from a repo checkout or an unpacked download):
#   sh agent/install-linux.sh
#
# After install:
#   vi /usr/local/etc/orbit-agent.conf   (set dashboard_url + agent_token)
#   systemctl enable --now orbit-agent

set -eu

INSTALL_DIR="/usr/local/orbit-agent"
CONFIG_FILE="/usr/local/etc/orbit-agent.conf"
UNIT_FILE="/etc/systemd/system/orbit-agent.service"

echo "=== orbit agent installer (Linux) ==="
echo ""

if [ "$(uname)" != "Linux" ]; then
    echo "ERROR: This installer is for Linux only (use install.sh on FreeBSD)."
    exit 1
fi
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: run as root (the agent needs root for updates/capture/shell)."
    exit 1
fi

# Python >= 3.8 (the agent's floor). Debian 11+/Ubuntu 20.04+/RHEL 9+ qualify.
echo "[1/5] Checking Python (no pip packages required)..."
PYTHON="$(command -v python3 || true)"
if [ -z "${PYTHON}" ]; then
    echo "ERROR: python3 not found. Install it (apt install python3 / dnf install python3)."
    exit 1
fi
if ! "${PYTHON}" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
    echo "ERROR: ${PYTHON} is older than 3.8 — this distro is below the supported floor."
    exit 1
fi
echo "  Using interpreter: ${PYTHON}"

echo "[2/5] Installing agent to ${INSTALL_DIR}..."
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${INSTALL_DIR}"
# Since the agent split (§28) Linux nodes run the linux line
# (orbit_agent_linux.py in the repo) — installed under the historical
# orbit_agent.py name so run-agent.sh and the systemd unit stay untouched.
if [ ! -f "${SCRIPT_DIR}/orbit_agent_linux.py" ]; then
    echo "ERROR: orbit_agent_linux.py not found in ${SCRIPT_DIR}"
    exit 1
fi
cp "${SCRIPT_DIR}/orbit_agent_linux.py" "${INSTALL_DIR}/orbit_agent.py"
chmod 755 "${INSTALL_DIR}/orbit_agent.py"
if [ ! -f "${SCRIPT_DIR}/run-agent.sh" ]; then
    echo "ERROR: run-agent.sh not found in ${SCRIPT_DIR}"
    exit 1
fi
cp "${SCRIPT_DIR}/run-agent.sh" "${INSTALL_DIR}/run-agent.sh"
chmod 755 "${INSTALL_DIR}/run-agent.sh"

# The vendored Checkmk agent does the actual data collection on Linux (DR-10).
# Without it the node still connects — it just pushes no system metrics.
echo "[3/5] Installing the bundled Checkmk agent..."
if [ -f "${SCRIPT_DIR}/vendor/check_mk_agent.linux" ]; then
    cp "${SCRIPT_DIR}/vendor/check_mk_agent.linux" "${INSTALL_DIR}/check_mk_agent.linux"
    chmod 755 "${INSTALL_DIR}/check_mk_agent.linux"
    command -v bash >/dev/null 2>&1 || \
        echo "  WARNING: bash not found — the Checkmk agent script needs it."
else
    echo "  WARNING: vendor/check_mk_agent.linux not found — skipping (no metrics)."
fi
command -v tcpdump >/dev/null 2>&1 || \
    echo "  NOTE: tcpdump not installed — packet capture will be unavailable."

echo "[4/5] Setting up configuration..."
mkdir -p "$(dirname "${CONFIG_FILE}")"
if [ ! -f "${CONFIG_FILE}" ]; then
    cat > "${CONFIG_FILE}" << 'CONF'
{
    "dashboard_url": "wss://dashboard.example.com/api/ws/agent",
    "agent_token": "PASTE_TOKEN_FROM_DASHBOARD_HERE",
    "agent_id": "",
    "push_interval": 120,
    "log_level": "INFO"
}
CONF
    chmod 600 "${CONFIG_FILE}"
    echo "  Created ${CONFIG_FILE} — edit it with your dashboard URL and token!"
else
    echo "  Config already exists at ${CONFIG_FILE}, not overwriting."
fi

echo "[5/5] Installing systemd unit..."
if [ ! -d /run/systemd/system ]; then
    echo "  WARNING: systemd not running — start ${INSTALL_DIR}/run-agent.sh yourself."
fi
if [ -f "${SCRIPT_DIR}/systemd/orbit-agent.service" ]; then
    cp "${SCRIPT_DIR}/systemd/orbit-agent.service" "${UNIT_FILE}"
    systemctl daemon-reload 2>/dev/null || true
else
    echo "ERROR: systemd/orbit-agent.service not found"
    exit 1
fi

echo "Done!"
echo ""
echo "=== Next steps ==="
echo "1. Edit config:    vi ${CONFIG_FILE}"
echo "   Set dashboard_url and agent_token from your dashboard."
echo ""
echo "2. Enable + start: systemctl enable --now orbit-agent"
echo "3. Check logs:     journalctl -u orbit-agent -f"
echo ""
