# Snapsec Agent Installation Script (Windows PowerShell)
# This script is intended to be populated by the backend with specific values.

$ErrorActionPreference = "Stop"

# --- Backend Populated Variables ---
$BACKEND_URL = "{{BACKEND_URL}}"
$API_KEY = "{{API_KEY}}"
$AGENT_VERSION = "{{AGENT_VERSION}}"
# ----------------------------------

$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "386" }
$RELEASE_BINARY_NAME = "agent"
$LOCAL_BINARY_NAME = "snapsec-detector.exe"
$INSTALL_DIR = "C:\Program Files\SnapsecDetector"
$CONFIG_DIR = "C:\ProgramData\snapsec.d"
$CONFIG_PATH = "$CONFIG_DIR\snapsec-detector.yaml"
$GITHUB_REPO = "snapsechq/snapsec-agents"
$BINARY_FILENAME = "${RELEASE_BINARY_NAME}_${AGENT_VERSION}_windows_${ARCH}"
$DOWNLOAD_URL = "https://github.com/${GITHUB_REPO}/releases/download/vs-agent/${AGENT_VERSION}/${BINARY_FILENAME}"

Write-Host "Installing Snapsec Detector for Windows ($ARCH)..." -ForegroundColor Cyan

# 1. Create Directories
if (!(Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR | Out-Null }
if (!(Test-Path $CONFIG_DIR)) { New-Item -ItemType Directory -Path $CONFIG_DIR | Out-Null }

# 2. Create Config File
Write-Host "Configuring detector..."
$ConfigContent = @"
backend_url: "$BACKEND_URL"
api_key: "$API_KEY"
interval: 5
"@
$ConfigContent | Out-File -FilePath $CONFIG_PATH -Encoding utf8

# 3. Download Binary
Write-Host "Downloading detector binary from $DOWNLOAD_URL..."
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile "$INSTALL_DIR\$LOCAL_BINARY_NAME"

# 4. Run Detector (Triggers Auto-Registration and Service Installation)
Write-Host "Starting registration and service installation..."
Start-Process -FilePath "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Wait -NoNewWindow

Write-Host "Snapsec Agent installation complete!" -ForegroundColor Green
