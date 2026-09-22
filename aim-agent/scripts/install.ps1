# Snapsec Agent Installation Script (Windows PowerShell)
# This script is intended to be populated by the backend with specific values.

$ErrorActionPreference = "Stop"

# --- Backend Populated Variables ---
$BACKEND_URL = "{{BACKEND_URL}}"
$API_KEY = "{{API_KEY}}"
$AGENT_VERSION = "{{AGENT_VERSION}}"
# ----------------------------------

$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "386" }
$BINARY_NAME = "agent"
$INSTALL_DIR = "C:\Program Files\SnapsecAgent"
$CONFIG_DIR = "C:\ProgramData\snapsec-agent"
$CONFIG_PATH = "$CONFIG_DIR\config.yaml"
$GITHUB_REPO = "faizanalibhat/aim-agent"
$BINARY_FILENAME = "${BINARY_NAME}_${AGENT_VERSION}_windows_${ARCH}"
$DOWNLOAD_URL = "https://github.com/${GITHUB_REPO}/releases/download/${AGENT_VERSION}/${BINARY_FILENAME}"

Write-Host "Installing Snapsec Agent for Windows ($ARCH)..." -ForegroundColor Cyan

# 1. Create Directories
if (!(Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null }
if (!(Test-Path $CONFIG_DIR)) { New-Item -ItemType Directory -Path $CONFIG_DIR | Out-Null }

# 2. Create Config File
Write-Host "Configuring agent..."
$ConfigContent = @"
backend_url: "$BACKEND_URL"
api_key: "$API_KEY"
interval: 5
"@
$ConfigContent | Out-File -FilePath $CONFIG_PATH -Encoding utf8

# 3. Download Binary
Write-Host "Downloading agent binary from $DOWNLOAD_URL..."
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile "$INSTALL_DIR\$BINARY_NAME"

# 4. Run Agent (Triggers Auto-Registration and Service Installation)
Write-Host "Starting registration and service installation..."
Start-Process -FilePath "$INSTALL_DIR\$BINARY_NAME" -Wait -NoNewWindow

Write-Host "Snapsec Agent installation complete!" -ForegroundColor Green
