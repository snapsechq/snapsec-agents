# How to Test the Agent's Vulnerability Scanner

This guide explains how developers can compile and test the `aim-agent` vulnerability scanning features (like Nuclei) locally.

## Prerequisite: Backend Services
Ensure that your backend services (AIM, VS, RabbitMQ, etc.) are running and accessible on your network before testing the agent.

---

## 🍎 Testing on macOS or 🐧 Linux (Native)

If you are developing on a macOS or Linux machine, you can run the agent natively.

1. **Build the agent:**
   ```bash
   go build -o bin/snapsec-agent ./cmd/agent
   ```
2. **Create your config file:**
   Create a configuration file at `/etc/snapsec-agent.yaml` (Linux) or `/usr/local/etc/snapsec-agent.yaml` (Mac) containing your API key and backend URL.
3. **Run the scan:**
   You must run it with elevated privileges because it needs access to read configuration files across the OS.
   ```bash
   sudo ./bin/aim-agent scan --tool=nuclei
   ```

---

## 🪟 Testing on Windows (Native)

> ⚠️ **IMPORTANT WARNING FOR WINDOWS USERS**
> Nuclei uses aggressive security testing templates. When running the agent directly on Windows, **Windows Defender** (or your antivirus) will very likely flag the agent or its downloaded templates as a threat and delete them.
> 
> You MUST either **temporarily disable Windows Defender Real-time Protection** while testing, or use a Linux Virtual Machine (see below).

1. **Build the agent:**
   ```powershell
   go build -o bin/snapsec-agent.exe ./cmd/agent
   ```
2. **Run the scan (requires Administrator PowerShell):**
   ```powershell
   .\bin\aim-agent.exe scan --tool=nuclei
   ```

---

## 💻 Testing via a Linux Virtual Machine (Recommended for Windows Users)

If you are on Windows and do not want to disable Windows Defender, you can test the agent by compiling it for Linux and running it inside a VM (like Kali Linux, Ubuntu, etc.).

### Step 1: Cross-compile for Linux (from your Windows host)
Open PowerShell in the `aim-agent` directory and run:
```powershell
$env:GOOS="linux"
$env:GOARCH="amd64"
go build -o bin/snapsec-agent-linux ./cmd/agent
```

### Step 2: Transfer to the VM
Copy the generated `bin/aim-agent-linux` file from your Windows host into your Linux VM (e.g., using Shared Folders, drag-and-drop, or SCP).

### Step 3: Configure the VM
In your Linux VM, create the configuration file so the agent knows how to talk to your Windows host.
```bash
sudo nano /etc/snapsec-agent.yaml
```
Add the following, ensuring the IP address matches your Windows machine's IP (use `ipconfig` on Windows to find it):
```yaml
# Replace WINDOWS_IP with your host machine's IP address
backend_url: "http://<WINDOWS_IP>:9999/asset-inventory/api/v1"
api_key: "your-valid-api-key"
```

### Step 4: Run the scan in the VM
Make the transferred binary executable and run it!
```bash
# Make it executable
chmod +x aim-agent-linux

# Run the scan (sudo is required to read system files)
sudo ./aim-agent-linux scan --tool=nuclei
```

As the scan runs, you will see Nuclei's progress in the terminal. When it completes, the results will automatically push to your Windows backend via the network!
