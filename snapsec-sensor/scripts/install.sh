#!/bin/bash

# Snapsec Sensor Installation Script (Linux/macOS)
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

case "$OS" in
    linux)
        OS="linux"
        ;;
    darwin)
        OS="darwin"
        ;;
    *)
        echo "Error: Unsupported operating system: ${OS}. Only Linux and macOS (Darwin) are supported." >&2
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH="amd64"
        ;;
    aarch64|arm64)
        ARCH="arm64"
        ;;
    *)
        echo "Error: Unsupported architecture: ${ARCH}. Only amd64 and arm64 are supported." >&2
        exit 1
        ;;
esac

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

# Stop running service if present (to avoid executable busy errors during replacement)
if [ "$OS" = "linux" ] && command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet snapsec-sensor 2>/dev/null; then
        echo "Stopping active snapsec-sensor service for update..."
        ${SUDO} systemctl stop snapsec-sensor || true
    fi
elif [ "$OS" = "darwin" ]; then
    if launchctl list snapsec-sensor >/dev/null 2>&1; then
        echo "Stopping active snapsec-sensor service for update..."
        ${SUDO} launchctl stop snapsec-sensor || true
    fi
fi

# 1. Create Directories and Configuration File
echo "[1/3] Writing sensor configuration to ${CONFIG_PATH}..."
${SUDO} mkdir -p "${CONFIG_DIR}"
${SUDO} mkdir -p "${INSTALL_DIR}"

# Preserve existing agent ID if config already exists
EXISTING_ID=""
if [ -f "${CONFIG_PATH}" ]; then
    EXISTING_ID=$(grep -E '^[[:space:]]*id:' "${CONFIG_PATH}" 2>/dev/null | head -n 1 | awk '{print $2}' | tr -d '"'\''')
fi

CONFIG_CONTENT="agent:
  enabled: true
  version: \"${AGENT_VERSION}\"
  update_channel: stable"

if [ -n "${EXISTING_ID}" ]; then
    CONFIG_CONTENT="${CONFIG_CONTENT}
  id: \"${EXISTING_ID}\""
fi

CONFIG_CONTENT="${CONFIG_CONTENT}

inventory:
  enabled: true
  interval: 300

vulnerability_scanning:
  enabled: false
  interval: 3600

communication:
  backend_url: \"${BACKEND_URL}\"
  asset_upstream: \"${ASSET_UPSTREAM}\"
  issues_upstream: \"${ISSUES_UPSTREAM}\"
  api_key: \"${API_KEY}\"
  heartbeat_interval: 60"

echo "${CONFIG_CONTENT}" | ${SUDO} tee "${CONFIG_PATH}" > /dev/null
${SUDO} chmod 600 "${CONFIG_PATH}"

# 2. Download Binary
echo "[2/3] Downloading sensor binary from ${DOWNLOAD_URL}..."
TMP_BIN="${INSTALL_DIR}/${LOCAL_BINARY_NAME}.tmp.$$"
${SUDO} curl -L -f -sS "${DOWNLOAD_URL}" -o "${TMP_BIN}"
${SUDO} chmod +x "${TMP_BIN}"
${SUDO} mv -f "${TMP_BIN}" "${INSTALL_DIR}/${LOCAL_BINARY_NAME}"

# 3. Run Sensor (Performs registration, updates agent.id, installs system service)
echo "[3/3] Initializing sensor registration and service installation..."
${SUDO} "${INSTALL_DIR}/${LOCAL_BINARY_NAME}"

if [ "$OS" = "darwin" ]; then
    echo "============================================================"
    echo " Snapsec Agent installed and started successfully!"
    echo " Service Status: ${SUDO} launchctl list | grep snapsec-sensor"
    echo " Live Logs:      ${SUDO} tail -f /var/log/snapsec-sensor*.log"
    echo "============================================================"
else
    echo "============================================================"
    echo " Snapsec Agent installed and started successfully!"
    echo " Service Status: ${SUDO} systemctl status snapsec-sensor"
    echo " Live Logs:      ${SUDO} journalctl -u snapsec-sensor -f"
    echo "============================================================"
fi
