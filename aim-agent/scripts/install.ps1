# Snapsec Agent Installation Script (Windows PowerShell)
# This script is intended to be populated by the backend with specific values.

$ErrorActionPreference = "Stop"

# --- Backend Populated Variables ---
$BACKEND_URL = "{{BACKEND_URL}}"
$API_KEY = "{{API_KEY}}"
$AGENT_VERSION = "{{AGENT_VERSION}}"
# ----------------------------------

$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "386" }
$RELEASE_BINARY_NAME = "snapsec-sensor"
$LOCAL_BINARY_NAME = "snapsec-sensor.exe"
$INSTALL_DIR = "C:\Program Files\SnapsecSensor"
$CONFIG_DIR = "C:\ProgramData\snapsec.d"
$CONFIG_PATH = "$CONFIG_DIR\snapsec-sensor.yaml"
$GITHUB_REPO = "snapsechq/snapsec-agents"
$BINARY_FILENAME = "${RELEASE_BINARY_NAME}_${AGENT_VERSION}_windows_${ARCH}"
$DOWNLOAD_URL = "https://github.com/${GITHUB_REPO}/releases/download/aim-agent/${AGENT_VERSION}/${BINARY_FILENAME}"

Write-Host "Installing Snapsec Sensor for Windows ($ARCH)..." -ForegroundColor Cyan

# 1. Create Directories
if (!(Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null }
if (!(Test-Path $CONFIG_DIR)) { New-Item -ItemType Directory -Path $CONFIG_DIR | Out-Null }

# 2. Create Config File
Write-Host "Configuring sensor..."
$ConfigContent = @"
backend_url: "$BACKEND_URL"
api_key: "$API_KEY"
interval: 5
"@
$ConfigContent | Out-File -FilePath $CONFIG_PATH -Encoding utf8

# 3. Download Binary
Write-Host "Downloading sensor binary from $DOWNLOAD_URL..."
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile "$INSTALL_DIR\$LOCAL_BINARY_NAME"

# 4. Run Sensor (Triggers Auto-Registration and Service Installation)
Write-Host "Starting registration and service installation..."
Start-Process -FilePath "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Wait -NoNewWindow

Write-Host "Snapsec Agent installation complete!" -ForegroundColor Green
