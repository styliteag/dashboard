#!/bin/sh
# install.sh — Install the opnsense-dash agent on an OPNsense firewall.
#
# Usage:
#   fetch -o - https://dashboard.example.com/agent/install.sh | sh
#   # or
#   curl -sS https://dashboard.example.com/agent/install.sh | sh
#
# After install, edit the config and enable the service:
#   vi /usr/local/etc/opnsense-dash-agent.conf   (set dashboard_url + agent_token)
#   sysrc opnsense_dash_agent_enable=YES
#   service opnsense_dash_agent start

set -eu

INSTALL_DIR="/usr/local/opnsense-dash-agent"
CONFIG_FILE="/usr/local/etc/opnsense-dash-agent.conf"
RC_SCRIPT="/usr/local/etc/rc.d/opnsense_dash_agent"

echo "=== opnsense-dash agent installer ==="
echo ""

# Check we're on FreeBSD / OPNsense
if [ "$(uname)" != "FreeBSD" ]; then
    echo "ERROR: This installer is for FreeBSD / OPNsense only."
    exit 1
fi

# Check Python — pfSense may ship only a versioned binary (python3.11), no python3.
PYTHON=""
for _py in python3 python3.11 python3.10 python3.9; do
    if command -v "${_py}" >/dev/null 2>&1; then
        PYTHON="$(command -v "${_py}")"
        break
    fi
done
if [ -z "${PYTHON}" ]; then
    echo "ERROR: no python3 interpreter found. Install it with: pkg install python311"
    exit 1
fi
echo "  Using interpreter: ${PYTHON}"

# No Python dependencies — the agent uses a stdlib-only WebSocket client (DR-4).
echo "[1/4] Checking Python (no pip packages required)..."

# Create install directory
echo "[2/4] Installing agent to ${INSTALL_DIR}..."
mkdir -p "${INSTALL_DIR}"

# Copy agent script (if running from repo checkout, use local file;
# otherwise this section would be replaced with a fetch from the dashboard)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
if [ -f "${SCRIPT_DIR}/opnsense_agent.py" ]; then
    cp "${SCRIPT_DIR}/opnsense_agent.py" "${INSTALL_DIR}/opnsense_agent.py"
else
    echo "ERROR: opnsense_agent.py not found in ${SCRIPT_DIR}"
    exit 1
fi
chmod 755 "${INSTALL_DIR}/opnsense_agent.py"

# Copy the supervisor (provides respawn + self-update rollback)
if [ -f "${SCRIPT_DIR}/run-agent.sh" ]; then
    cp "${SCRIPT_DIR}/run-agent.sh" "${INSTALL_DIR}/run-agent.sh"
    chmod 755 "${INSTALL_DIR}/run-agent.sh"
else
    echo "ERROR: run-agent.sh not found in ${SCRIPT_DIR}"
    exit 1
fi

# Copy example config if no config exists
echo "[3/4] Setting up configuration..."
if [ ! -f "${CONFIG_FILE}" ]; then
    if [ -f "${SCRIPT_DIR}/opnsense-dash-agent.conf.example" ]; then
        cp "${SCRIPT_DIR}/opnsense-dash-agent.conf.example" "${CONFIG_FILE}"
    else
        cat > "${CONFIG_FILE}" << 'CONF'
{
    "dashboard_url": "wss://dashboard.example.com/api/ws/agent",
    "agent_token": "PASTE_TOKEN_FROM_DASHBOARD_HERE",
    "agent_id": "",
    "push_interval": 30,
    "log_level": "INFO"
}
CONF
    fi
    echo "  Created ${CONFIG_FILE} — edit it with your dashboard URL and token!"
else
    echo "  Config already exists at ${CONFIG_FILE}, not overwriting."
fi

# Install rc.d script
echo "[4/4] Installing service script..."
if [ -f "${SCRIPT_DIR}/rc.d/opnsense_dash_agent" ]; then
    cp "${SCRIPT_DIR}/rc.d/opnsense_dash_agent" "${RC_SCRIPT}"
else
    echo "ERROR: rc.d/opnsense_dash_agent not found"
    exit 1
fi
chmod 755 "${RC_SCRIPT}"

echo "Done!"
echo ""
echo "=== Next steps ==="
echo "1. Edit config:    vi ${CONFIG_FILE}"
echo "   Set dashboard_url and agent_token from your dashboard."
echo ""
echo "2. Enable service: sysrc opnsense_dash_agent_enable=YES"
echo "3. Start agent:    service opnsense_dash_agent start"
echo "4. Check logs:     tail -f /var/log/opnsense_dash_agent.log"
echo ""
