# Snapsec Sensor Installation Script (Windows PowerShell)
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

# Detect Architecture
$ARCH = if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") {
    "arm64"
} elseif ($env:PROCESSOR_ARCHITECTURE -eq "AMD64" -or (Test-Path env:PROCESSOR_ARCHITEW6432)) {
    "amd64"
} else {
    Write-Error "Unsupported architecture: $env:PROCESSOR_ARCHITECTURE. Only amd64 and arm64 are supported."
    exit 1
}

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

# Stop running service if present (to avoid executable busy errors during replacement)
$existingService = Get-Service -Name "snapsec-sensor" -ErrorAction SilentlyContinue
if ($existingService -and $existingService.Status -eq 'Running') {
    Write-Host "Stopping active snapsec-sensor service for update..." -ForegroundColor Yellow
    Stop-Service -Name "snapsec-sensor" -Force -ErrorAction SilentlyContinue
}

# 1. Create Directories
Write-Host "[1/3] Creating directories and writing configuration..." -ForegroundColor Yellow
if (!(Test-Path $INSTALL_DIR)) { New-Item -ItemType Directory -Path $INSTALL_DIR -Force | Out-Null }
if (!(Test-Path $CONFIG_DIR)) { New-Item -ItemType Directory -Path $CONFIG_DIR -Force | Out-Null }

# Preserve existing agent ID if config already exists
$ExistingAgentId = ""
if (Test-Path $CONFIG_PATH) {
    $matched = Select-String -Path $CONFIG_PATH -Pattern '^\s*id:\s*["'']?([^"''\r\n]+)["'']?' | Select-Object -First 1
    if ($matched -and $matched.Matches[0].Groups[1].Value) {
        $ExistingAgentId = $matched.Matches[0].Groups[1].Value.Trim()
    }
}

# 2. Create Config File
$ConfigContent = @"
agent:
  enabled: true
  version: "$AGENT_VERSION"
  update_channel: stable
"@

if ($ExistingAgentId) {
    $ConfigContent += "`n  id: `"$ExistingAgentId`""
}

$ConfigContent += @"

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

[System.IO.File]::WriteAllText($CONFIG_PATH, $ConfigContent, [System.Text.UTF8Encoding]::new($false))

# 3. Download Binary
Write-Host "[2/3] Downloading sensor binary from $DOWNLOAD_URL..." -ForegroundColor Yellow
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$tempFile = "$INSTALL_DIR\$LOCAL_BINARY_NAME.tmp"
Invoke-WebRequest -Uri $DOWNLOAD_URL -OutFile $tempFile -UseBasicParsing
if (Test-Path "$INSTALL_DIR\$LOCAL_BINARY_NAME") {
    Remove-Item -Path "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Force
}
Move-Item -Path $tempFile -Destination "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Force

# 4. Run Sensor (Performs registration, updates agent.id, installs Windows service)
Write-Host "[3/3] Initializing sensor registration and service installation..." -ForegroundColor Yellow
Start-Process -FilePath "$INSTALL_DIR\$LOCAL_BINARY_NAME" -Wait -NoNewWindow

Write-Host "============================================================" -ForegroundColor Green
Write-Host " Snapsec Agent installed and started successfully!" -ForegroundColor Green
Write-Host " Service Status: Get-Service snapsec-sensor" -ForegroundColor Green
Write-Host " Restart:        Restart-Service snapsec-sensor" -ForegroundColor Green
Write-Host " Live Logs:      Get-EventLog -LogName Application -Source `"snapsec-sensor`" -Newest 20" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
