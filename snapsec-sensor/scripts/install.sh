#!/bin/bash

# Snapsec Agent Installation Script (Linux/macOS)
# This script is populated by the backend with organization-specific parameters.

set -e

# --- Backend Populated Variables ---
BACKEND_URL="{{BACKEND_URL}}"
ASSET_UPSTREAM="{{ASSET_UPSTREAM}}"
ISSUES_UPSTREAM="{{ISSUES_UPSTREAM}}"
API_KEY="{{API_KEY}}"
AGENT_VERSION="{{AGENT_VERSION}}"
# ----------------------------------

# Resolve privilege escalation command
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    if command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        echo "Error: This script must be run as root or with sudo installed." >&2
        exit 1
    fi
fi

# Detect Operating System and Architecture
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
elif [ "$ARCH" = "i386" ] || [ "$ARCH" = "i686" ]; then
    ARCH="386"
fi

RELEASE_BINARY_NAME="snapsec-sensor"
LOCAL_BINARY_NAME="snapsec-sensor"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/snapsec.d"
CONFIG_PATH="${CONFIG_DIR}/snapsec-sensor.yaml"
GITHUB_REPO="snapsechq/snapsec-agents"
BINARY_FILENAME="${RELEASE_BINARY_NAME}_${AGENT_VERSION}_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${AGENT_VERSION}/${BINARY_FILENAME}"

echo "============================================================"
echo " Installing Snapsec Sensor v${AGENT_VERSION} for ${OS} (${ARCH})"
echo "============================================================"

# 1. Create Directories and Configuration File
echo "[1/3] Writing sensor configuration to ${CONFIG_PATH}..."
${SUDO} mkdir -p "${CONFIG_DIR}"
${SUDO} mkdir -p "${INSTALL_DIR}"

cat <<EOF | ${SUDO} tee "${CONFIG_PATH}" > /dev/null
agent:
  enabled: true
  version: "${AGENT_VERSION}"
  update_channel: stable

inventory:
  enabled: true
  interval: 300

vulnerability_scanning:
  enabled: false
  interval: 3600

communication:
  backend_url: "${BACKEND_URL}"
  asset_upstream: "${ASSET_UPSTREAM}"
  issues_upstream: "${ISSUES_UPSTREAM}"
  api_key: "${API_KEY}"
  heartbeat_interval: 60
EOF

${SUDO} chmod 600 "${CONFIG_PATH}"

# 2. Download Binary
echo "[2/3] Downloading sensor binary from ${DOWNLOAD_URL}..."
${SUDO} curl -L -f -sS "${DOWNLOAD_URL}" -o "${INSTALL_DIR}/${LOCAL_BINARY_NAME}"
${SUDO} chmod +x "${INSTALL_DIR}/${LOCAL_BINARY_NAME}"

# 3. Run Sensor (Performs registration, updates agent.id, installs system service)
echo "[3/3] Initializing sensor registration and service installation..."
${SUDO} "${INSTALL_DIR}/${LOCAL_BINARY_NAME}"

echo "============================================================"
echo " Snapsec Agent installed and started successfully!"
echo " Service Status: ${SUDO} systemctl status snapsec-sensor"
echo " Live Logs:      ${SUDO} journalctl -u snapsec-sensor -f"
echo "============================================================"
