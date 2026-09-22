#!/bin/bash

# Snapsec Agent Installation Script (Linux/macOS)
# This script is intended to be populated by the backend with specific values.

set -e

# --- Backend Populated Variables ---
BACKEND_URL="{{BACKEND_URL}}"
API_KEY="{{API_KEY}}"
AGENT_VERSION="{{AGENT_VERSION}}"
# ----------------------------------

# Detect OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

if [ "$ARCH" = "x86_64" ]; then
    ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    ARCH="arm64"
fi

RELEASE_BINARY_NAME="agent"
LOCAL_BINARY_NAME="snapsec-sensor"
CONFIG_DIR="/etc/snapsec.d"
CONFIG_PATH="${CONFIG_DIR}/snapsec-sensor.yaml"
GITHUB_REPO="snapsechq/snapsec-agents"
BINARY_FILENAME="${RELEASE_BINARY_NAME}_${AGENT_VERSION}_${OS}_${ARCH}"
DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/aim-agent/${AGENT_VERSION}/${BINARY_FILENAME}"

echo "Installing Snapsec Sensor for ${OS} (${ARCH})..."

# 1. Create Config Directory and File
echo "Configuring sensor..."
sudo mkdir -p "${CONFIG_DIR}"
cat <<EOF | sudo tee ${CONFIG_PATH} > /dev/null
backend_url: "${BACKEND_URL}"
api_key: "${API_KEY}"
interval: 5
EOF

# 2. Download Binary
echo "Downloading sensor binary from ${DOWNLOAD_URL}..."
sudo curl -L -f "${DOWNLOAD_URL}" -o "/usr/local/bin/${LOCAL_BINARY_NAME}"
sudo chmod +x "/usr/local/bin/${LOCAL_BINARY_NAME}"

# 3. Run Sensor (Triggers Auto-Registration and Service Installation)
echo "Starting registration and service installation..."
sudo "/usr/local/bin/${LOCAL_BINARY_NAME}"

echo "Snapsec Agent installation complete!"
