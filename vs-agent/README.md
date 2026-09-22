# Snapsec Detector (vs-agent)

A cross-platform vulnerability scanning agent written in Go.

## Features

- **Cross-platform Service**: Supports Linux, Windows, and macOS service registration as `snapsec-detector`.
- **Automated Registration**: Registers itself with the backend on first run.
- **Silent Background Scanning**: Optimized for an extremely low CPU and Memory footprint.

## Configuration

The configuration file is expected to be at:
- Linux/Mac: `/etc/snapsec.d/snapsec-detector.yaml`
- Windows: `C:\ProgramData\snapsec.d\snapsec-detector.yaml`

To run manually:
```bash
sudo ./snapsec-detector
```

## Scanning Engine Configuration

The agent includes a highly optimized Nuclei scanning engine designed to run silently in the background without disrupting the host machine's performance.

### Performance Throttling
To prevent CPU spikes and memory exhaustion (OOM), the Nuclei engine is hardcoded with the following "sweet spot" configuration for endpoint agents:
- **`-c 8` (Concurrency)**: Runs exactly 8 vulnerability templates simultaneously. This bounds memory strictly under 100MB.
- **`-bs 8` (Batch Size)**: Processes 8 files at a time per template. This prevents the OS from running out of file descriptors.
- **`-rl 100` (Rate Limiting)**: Caps the scanner to 100 file reads/regex evaluations per second. This serves as a natural throttle to ensure the user's CPU never spikes to 100%.
- **No Timeout**: The 2-hour timeout limit has been removed, ensuring full filesystem scans can complete even if heavily throttled.

### Resuming Interrupted Scans
If the agent is forcefully killed, crashes, or the host machine reboots during a scan, you can resume exactly where it left off. Nuclei automatically generates a state file when interrupted.

To resume an interrupted scan manually:
```bash
sudo ./snapsec-detector scan --tool=nuclei --target=/ --resume=path/to/resume.cfg
```
