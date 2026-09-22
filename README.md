# Snapsec Agents Monorepo

Welcome to the Snapsec Agents repository! This is a monorepo containing all the endpoint agents used within the Snapsec ecosystem.

## Available Agents

- **[aim-agent](./aim-agent/) (Snapsec Sensor)**: The Asset Inventory Management agent. It runs quietly in the background to monitor system assets, hardware, network interfaces, and reports heartbeats back to the Snapsec backend.
- **[vs-agent](./vs-agent/) (Snapsec Detector)**: The Vulnerability Scanner agent. A highly optimized, background vulnerability scanner using the Nuclei engine to scan the host filesystem for security issues without degrading host performance.

## Releasing

We use a **Tag Prefix** approach with GoReleaser to handle deterministic, isolated releases for each agent. 

See the [RELEASE.md](./RELEASE.md) file for comprehensive instructions on how to trigger agent releases.
