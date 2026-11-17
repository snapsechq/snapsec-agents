# Snapsec Agent Installation Script (Windows PowerShell)
# This script is populated by the backend with organization-specific parameters.

$ErrorActionPreference = "Stop"

# --- Backend Populated Variables ---
$BACKEND_URL = "{{BACKEND_URL}}"
$ASSET_UPSTREAM = "{{ASSET_UPSTREAM}}"
$ISSUES_UPSTREAM = "{{ISSUES_UPSTREAM}}"
$API_KEY = "{{API_KEY}}"
$AGENT_VERSION = "{{AGENT_VERSION}}"
# ----------------------------------

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Error: This script must be run with Administrator privileges. Please re-run PowerShell as Administrator."
    exit 1
}

$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "AMD64") { "amd64" } else { "386" }
$RELEASE_BINARY_NAME = "snapsec-sensor"
$LOCAL_BINARY_NAME = "snapsec-sensor.exe"
$INSTALL_DIR = "C:\Program Files\SnapsecSensor"
$CONFIG_DIR = "C:\ProgramData\snapsec.d"
$CONFIG_PATH = "$CONFIG_DIR\snapsec-sensor.yaml"
$GITHUB_REPO = "snapsechq/snapsec-agents"
$BINARY_FILENAME = "${RELEASE_BINARY_NAME}_${AGENT_VERSION}_windows_${ARCH}.exe"
$DOWNLOAD_URL = "https://github.com/${GITHUB_REPO}/releases/download/v${AGENT_VERSION}/${BINARY_FILENAME}"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Installing Snapsec Sensor v$AGENT_VERSION for Windows ($ARCH)" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# 1. Create Directories
Write-Host "[1/3] Creating directories and writing configuration..." -ForegroundColor Yellow
if (!(Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
if (!(Test-Path $CONFIG_DIR)) { New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null }

# 2. Create Config File
$ConfigContent = @"
agent:
  enabled: true
  version: "$AGENT_VERSION"
  update_channel: stable

inventory:
  enabled: true
  interval: 300

vulnerability_scanning:
  enabled: false
  interval: 3600

communication:
  backend_url: "$BACKEND_URL"
  asset_upstream: "$ASSET_UPSTREAM"
  issues_upstream: "$ISSUES_UPSTREAM"
  api_key: "$API_KEY"
  heartbeat_interval: 60
"@
$ConfigContent | Out-File -FilePath $CONFIG_PATH -Encoding utf8

# 3. Download Binary
Write-Host "[2/3] Downloading sensor binary from $DOWNLOAD_URL..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile "$INSTALL_DIR\$LOCAL_BINARY_NAME"

# 4. Run Sensor (Performs registration, updates agent.id, installs Windows service)
Write-Host "[3/3] Initializing sensor registration and service installation..." -ForegroundColor Yellow
Start-Process -FilePath "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Wait -NoNewWindow

Write-Host "============================================================" -ForegroundColor Green
Write-Host " Snapsec Agent installed and started successfully!" -ForegroundColor Green
Write-Host " Service Status: Get-Service snapsec-sensor" -ForegroundColor Green
Write-Host " Restart:        Restart-Service snapsec-sensor" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
