package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"runtime"
	"snapsec-agent/internal/config"
	"snapsec-agent/internal/detector"
	"snapsec-agent/internal/modules"
	"snapsec-agent/internal/modules/classification"
	"snapsec-agent/internal/modules/devices"
	"snapsec-agent/internal/modules/hardware"
	"snapsec-agent/internal/modules/host"
	"snapsec-agent/internal/modules/network"
	"snapsec-agent/internal/modules/packages"
	"snapsec-agent/internal/modules/processes"
	"snapsec-agent/internal/modules/security"
	"snapsec-agent/internal/modules/services"
	"snapsec-agent/internal/modules/users"
	"snapsec-agent/internal/updater"
	"snapsec-agent/pkg/api"
	"time"
)

type Agent struct {
	cfg           *config.Config
	configPath    string
	api           *api.Client
	modules       []modules.Module
	stop          chan struct{}
	KillHandler   func()
	UpdateHandler func() error
	detectorMgr   *detector.Manager
	scanInterval  int
	scanEnabled   bool
}

func NewAgent(cfg *config.Config, configPath string) *Agent {
	return &Agent{
		cfg:        cfg,
		configPath: configPath,
		api: api.NewClientWithUpstreams(
			cfg.Communication.BackendURL,
			cfg.Communication.AssetUpstream,
			cfg.Communication.IssuesUpstream,
			cfg.Communication.APIKey,
		),
		modules: []modules.Module{
			&host.HostModule{},
			&hardware.HardwareModule{},
			&network.NetworkModule{},
			&processes.ProcessesModule{},
			&packages.PackagesModule{},
			&services.ServicesModule{},
			&devices.DevicesModule{},
			&users.UsersModule{},
			&security.SecurityModule{},
			&classification.ClassificationModule{},
		},
		stop:         make(chan struct{}),
		detectorMgr:  detector.NewManager(configPath),
		scanInterval: cfg.VulnerabilityScanning.Interval,
		scanEnabled:  cfg.VulnerabilityScanning.Enabled,
	}
}

func (a *Agent) RegisterOnly() error {
	hostname, _ := os.Hostname()

	// Gather basic info for registration
	var osName, ipAddress string

	// Use host module for OS info
	hostMod := &host.HostModule{}
	hostData, err := hostMod.Gather()
	if err == nil {
		if m, ok := hostData.(map[string]interface{}); ok {
			if osInfo, ok := m["os"].(host.OSData); ok {
				osName = osInfo.Name
			}
		}
	}
	if osName == "" {
		osName = runtime.GOOS
	}

	// Use network module for IP info
	netMod := &network.NetworkModule{}
	netData, err := netMod.Gather()
	if err == nil {
		if n, ok := netData.(network.NetworkData); ok {
			for _, i := range n.Interfaces {
				if i.Name != "lo" && len(i.IPv4) > 0 {
					ipAddress = i.IPv4[0]
					break
				}
			}
		}
	}

	// Determine architecture
	architecture := "linux"
	switch runtime.GOOS {
	case "darwin":
		architecture = "macos"
	case "windows":
		architecture = "windows"
	default:
		architecture = "linux"
	}

	arch := runtime.GOARCH

	version := a.cfg.Agent.Version
	if version == "" {
		version = config.Version
	}

	log.Printf("Registering agent with hostname: %s, os: %s, architecture: %s, arch: %s, ip: %s", hostname, osName, architecture, arch, ipAddress)

	inventory, gErr := a.gatherAll()
	if gErr != nil {
		log.Printf("Failed to gather inventory for registration: %v", gErr)
		inventory = nil
	}

	agentID, err := a.api.Register(hostname, osName, version, ipAddress, architecture, arch, inventory)
	if err != nil {
		return err
	}

	log.Printf("Registration successful. Assigned Agent ID: %s", agentID)
	a.cfg.Agent.ID = agentID
	a.cfg.AgentID = agentID

	// Save the agent ID back to the config file
	if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
		return fmt.Errorf("failed to save config with agent ID: %w", err)
	}

	return nil
}

func (a *Agent) checkVulnHeartbeat() bool {
	agentID := a.cfg.Agent.ID
	if agentID == "" {
		agentID = a.cfg.AgentID
	}
	if agentID == "" {
		return false
	}

	version := a.cfg.Agent.Version
	if version == "" {
		version = config.Version
	}

	resp, err := a.api.VulnHeartbeat(agentID, version)
	if err != nil {
		if httpErr, ok := err.(*api.HTTPError); ok && httpErr.StatusCode == 404 {
			if a.cfg.VulnerabilityScanning.Enabled {
				log.Println("[Agent] Vuln upstream returned 404 (project not found). Disabling vulnerability scanning.")
				a.cfg.VulnerabilityScanning.Enabled = false
				a.scanEnabled = false
				_ = config.SaveConfig(a.configPath, a.cfg)
				return true
			}
			log.Println("[Agent] Vuln upstream returned 404 (no config). Vulnerability scanning remains disabled.")
			return false
		}
		log.Printf("[Agent] Vuln heartbeat error: %v", err)
		return false
	}

	changed := false
	enabled := true
	if resp.Configuration.VulnerabilityScanning != nil && resp.Configuration.VulnerabilityScanning.Enabled != nil {
		enabled = *resp.Configuration.VulnerabilityScanning.Enabled
	} else if resp.Configuration.Enabled != nil {
		enabled = *resp.Configuration.Enabled
	}

	if a.cfg.VulnerabilityScanning.Enabled != enabled {
		a.cfg.VulnerabilityScanning.Enabled = enabled
		a.scanEnabled = enabled
		changed = true
	}

	interval := 0
	if resp.Configuration.VulnerabilityScanning != nil && resp.Configuration.VulnerabilityScanning.Interval > 0 {
		interval = resp.Configuration.VulnerabilityScanning.Interval
	} else if resp.Configuration.Interval > 0 {
		interval = resp.Configuration.Interval
	}

	if interval > 0 && interval != a.cfg.VulnerabilityScanning.Interval {
		a.cfg.VulnerabilityScanning.Interval = interval
		a.scanInterval = interval
		changed = true
	}

	if changed {
		log.Printf("[Agent] Vuln configuration updated from upstream: enabled=%v, interval=%ds",
			a.cfg.VulnerabilityScanning.Enabled, a.cfg.VulnerabilityScanning.Interval)
		if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
			log.Printf("[Agent] Failed to save updated configuration: %v", err)
		}
	} else if enabled {
		log.Printf("[Agent] Vuln heartbeat acknowledged. Vulnerability scanning is active (interval: %ds)", a.cfg.VulnerabilityScanning.Interval)
	}

	return changed
}

func (a *Agent) CheckVulnHeartbeatExported() bool {
	return a.checkVulnHeartbeat()
}

func (a *Agent) Start() error {
	log.Println("Starting Snapsec Agent...")

	// 1. Ensure we have an Agent ID
	if a.cfg.Agent.ID == "" && a.cfg.AgentID == "" {
		if err := a.RegisterOnly(); err != nil {
			return fmt.Errorf("failed to register during start: %w", err)
		}
	}

	agentID := a.cfg.Agent.ID
	if agentID == "" {
		agentID = a.cfg.AgentID
	}
	version := a.cfg.Agent.Version
	if version == "" {
		version = config.Version
	}

	// Ensure configuration on disk is persisted in the sectioned structure
	if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
		log.Printf("Note: could not re-save configuration format: %v", err)
	}

	// 2. Start Heartbeat, Inventory Reporting, and Vulnerability Scan Loops
	hbTicker := time.NewTicker(time.Duration(a.cfg.Communication.HeartbeatInterval) * time.Second)
	inventoryTicker := time.NewTicker(time.Duration(a.cfg.Inventory.Interval) * time.Second)
	scanTicker := time.NewTicker(time.Duration(a.cfg.VulnerabilityScanning.Interval) * time.Second)
	defer hbTicker.Stop()
	defer inventoryTicker.Stop()
	defer scanTicker.Stop()

	log.Printf("Communication Heartbeat interval: %ds, Inventory interval: %ds, Scan interval: %ds",
		a.cfg.Communication.HeartbeatInterval, a.cfg.Inventory.Interval, a.cfg.VulnerabilityScanning.Interval)
	log.Printf("Vulnerability scanning enabled: %v, Inventory enabled: %v",
		a.cfg.VulnerabilityScanning.Enabled, a.cfg.Inventory.Enabled)

	// 3. Initial Heartbeat to Asset Upstream
	if resp, err := a.api.Heartbeat(agentID, version); err == nil {
		if a.checkKill(resp) {
			return nil
		}
		if a.syncConfiguration(resp) {
			hbTicker.Reset(time.Duration(a.cfg.Communication.HeartbeatInterval) * time.Second)
			inventoryTicker.Reset(time.Duration(a.cfg.Inventory.Interval) * time.Second)
		}
	} else {
		log.Printf("Initial asset heartbeat failed: %v", err)
	}

	// 4. Initial Heartbeat to Vuln Upstream
	if a.checkVulnHeartbeat() {
		scanTicker.Reset(time.Duration(a.cfg.VulnerabilityScanning.Interval) * time.Second)
	}

	// 5. Initial Asset Inventory Push
	if a.cfg.Inventory.Enabled {
		log.Println("Gathering and sending initial asset results...")
		if payload, err := a.gatherAll(); err == nil {
			if resp, err := a.api.SendResults(agentID, payload); err != nil {
				log.Printf("Failed to send initial asset results: %v", err)
			} else {
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					hbTicker.Reset(time.Duration(a.cfg.Communication.HeartbeatInterval) * time.Second)
					inventoryTicker.Reset(time.Duration(a.cfg.Inventory.Interval) * time.Second)
				}
			}
		} else {
			log.Printf("Failed to gather initial results: %v", err)
		}
	} else {
		log.Println("[Agent] Inventory gathering is disabled. Skipping initial asset push.")
	}

	// 6. Initial Host Security Detector Scan (only if vulnerability scanning is enabled!)
	if a.cfg.VulnerabilityScanning.Enabled {
		log.Println("Vulnerability scanning is enabled. Running initial host security detector scan...")
		go func() {
			findings, err := a.detectorMgr.RunAll(context.Background())
			if err != nil {
				log.Printf("[Agent] Initial detector scan error: %v", err)
				return
			}
			log.Printf("[Agent] Initial detector scan found %d security issues", len(findings))
			if len(findings) > 0 {
				if resp, err := a.api.SendVulnerabilities(agentID, findings); err != nil {
					log.Printf("[Agent] Failed to send initial vulnerabilities: %v", err)
				} else {
					a.syncConfiguration(resp)
				}
			}
		}()
	} else {
		log.Println("[Agent] Vulnerability scanning is disabled by default. Skipping initial detector scan.")
	}

	// 7. Event Loop
	for {
		select {
		case <-hbTicker.C:
			// Send Heartbeat to Asset Upstream
			resp, err := a.api.Heartbeat(agentID, version)
			if err != nil {
				log.Printf("Heartbeat failed: %v", err)
			} else {
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated from asset heartbeat. Heartbeat: %ds, Inventory: %ds",
						a.cfg.Communication.HeartbeatInterval, a.cfg.Inventory.Interval)
					hbTicker.Reset(time.Duration(a.cfg.Communication.HeartbeatInterval) * time.Second)
					inventoryTicker.Reset(time.Duration(a.cfg.Inventory.Interval) * time.Second)
				}
			}

			// Send Heartbeat to Vuln Upstream
			if a.checkVulnHeartbeat() {
				scanTicker.Reset(time.Duration(a.cfg.VulnerabilityScanning.Interval) * time.Second)
			}

		case <-inventoryTicker.C:
			if !a.cfg.Inventory.Enabled {
				continue
			}

			// Gather and Send Results to Asset Upstream
			results, err := a.gatherAll()
			if err != nil {
				log.Printf("Failed to gather inventory results: %v", err)
				continue
			}

			resp, err := a.api.SendResults(agentID, results)
			if err != nil {
				log.Printf("Failed to send asset results to asset upstream: %v", err)
			} else {
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated from results response. Heartbeat: %ds, Inventory: %ds",
						a.cfg.Communication.HeartbeatInterval, a.cfg.Inventory.Interval)
					hbTicker.Reset(time.Duration(a.cfg.Communication.HeartbeatInterval) * time.Second)
					inventoryTicker.Reset(time.Duration(a.cfg.Inventory.Interval) * time.Second)
				}
			}

			// If vulnerability scanning is enabled, also sync latest findings to issues upstream
			if a.cfg.VulnerabilityScanning.Enabled && a.api.IssuesUpstream != "" {
				if findings := a.detectorMgr.LastFindings(); len(findings) > 0 {
					if _, err := a.api.SendVulnerabilities(agentID, findings); err != nil {
						log.Printf("Failed to sync findings to issues upstream: %v", err)
					}
				}
			}

		case <-scanTicker.C:
			if !a.cfg.VulnerabilityScanning.Enabled {
				log.Println("[Agent] Vulnerability scanning is disabled. Skipping scheduled scan.")
				continue
			}

			log.Println("[Agent] Triggering host security detector scan...")
			go func() {
				findings, err := a.detectorMgr.RunAll(context.Background())
				if err != nil {
					log.Printf("[Agent] Host detector scan error: %v", err)
				} else {
					log.Printf("[Agent] Host detector scan finished with %d findings", len(findings))
					if len(findings) > 0 {
						if resp, err := a.api.SendVulnerabilities(agentID, findings); err != nil {
							log.Printf("[Agent] Failed to send vulnerabilities to issues upstream: %v", err)
						} else {
							log.Printf("[Agent] Successfully sent %d findings to issues upstream", len(findings))
							a.syncConfiguration(resp)
						}
					}
				}
			}()

		case <-a.stop:
			log.Println("Stopping agent...")
			return nil
		}
	}
}

func (a *Agent) Stop() {
	close(a.stop)
}

func (a *Agent) syncConfiguration(resp *api.ResultsResponse) bool {
	if resp == nil {
		return false
	}

	changed := false

	// Check sectioned configs first if present
	if resp.Configuration.Communication != nil {
		if resp.Configuration.Communication.HeartbeatInterval > 0 &&
			resp.Configuration.Communication.HeartbeatInterval != a.cfg.Communication.HeartbeatInterval {
			a.cfg.Communication.HeartbeatInterval = resp.Configuration.Communication.HeartbeatInterval
			changed = true
		}
		if resp.Configuration.Communication.AssetUpstream != "" &&
			resp.Configuration.Communication.AssetUpstream != a.cfg.Communication.AssetUpstream {
			a.cfg.Communication.AssetUpstream = resp.Configuration.Communication.AssetUpstream
			a.api.AssetUpstream = resp.Configuration.Communication.AssetUpstream
			changed = true
		}
		if resp.Configuration.Communication.IssuesUpstream != "" &&
			resp.Configuration.Communication.IssuesUpstream != a.cfg.Communication.IssuesUpstream {
			a.cfg.Communication.IssuesUpstream = resp.Configuration.Communication.IssuesUpstream
			a.api.IssuesUpstream = resp.Configuration.Communication.IssuesUpstream
			changed = true
		}
	}
	if resp.Configuration.Inventory != nil {
		if resp.Configuration.Inventory.Interval > 0 &&
			resp.Configuration.Inventory.Interval != a.cfg.Inventory.Interval {
			a.cfg.Inventory.Interval = resp.Configuration.Inventory.Interval
			changed = true
		}
	}

	// Legacy / flat field sync
	if resp.Configuration.HeartbeatInterval > 0 && resp.Configuration.HeartbeatInterval != a.cfg.Communication.HeartbeatInterval {
		a.cfg.Communication.HeartbeatInterval = resp.Configuration.HeartbeatInterval
		changed = true
	}
	if resp.Configuration.AssetPushInterval > 0 && resp.Configuration.AssetPushInterval != a.cfg.Inventory.Interval {
		a.cfg.Inventory.Interval = resp.Configuration.AssetPushInterval
		changed = true
	}

	// Update Upstream Routing
	if resp.Configuration.AssetUpstream != "" && resp.Configuration.AssetUpstream != a.cfg.Communication.AssetUpstream {
		a.cfg.Communication.AssetUpstream = resp.Configuration.AssetUpstream
		a.api.AssetUpstream = resp.Configuration.AssetUpstream
		changed = true
	}
	if resp.Configuration.IssuesUpstream != "" && resp.Configuration.IssuesUpstream != a.cfg.Communication.IssuesUpstream {
		a.cfg.Communication.IssuesUpstream = resp.Configuration.IssuesUpstream
		a.api.IssuesUpstream = resp.Configuration.IssuesUpstream
		changed = true
	}
	if a.cfg.Communication.IssuesUpstream == "" && resp.Configuration.ScanAgent != nil && resp.Configuration.ScanAgent.BackendURL != "" {
		a.cfg.Communication.IssuesUpstream = resp.Configuration.ScanAgent.BackendURL
		a.api.IssuesUpstream = resp.Configuration.ScanAgent.BackendURL
		changed = true
	}

	if changed {
		if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
			log.Printf("Failed to save updated configuration: %v", err)
		}
	}

	// Check for Software Updates
	currentVersion := a.cfg.Agent.Version
	if currentVersion == "" {
		currentVersion = config.Version
	}
	if currentVersion != "dev" && resp.Configuration.LatestVersion != "" && resp.Configuration.LatestVersion != currentVersion {
		log.Printf("New version available: %s (current: %s). Starting auto-update...", resp.Configuration.LatestVersion, currentVersion)
		if resp.Configuration.DownloadURL == "" {
			log.Printf("Download URL is empty. Update aborted.")
			return changed
		}

		if err := updater.Update(resp.Configuration.DownloadURL); err != nil {
			log.Printf("Update failed: %v", err)
			return changed
		}

		log.Println("Update successful. Triggering agent restart...")
		if a.UpdateHandler != nil {
			if err := a.UpdateHandler(); err != nil {
				log.Printf("Failed to trigger restart: %v", err)
			}
		} else {
			log.Println("UpdateHandler not set. Manual restart required.")
		}
	}

	return changed
}

func (a *Agent) checkKill(resp *api.ResultsResponse) bool {
	if resp != nil && resp.Configuration.Kill {
		log.Println("Kill signal received from backend. Initiating shutdown...")
		if a.KillHandler != nil {
			a.KillHandler()
		} else {
			os.Exit(0)
		}
		return true
	}
	return false
}

func (a *Agent) gatherAll() (map[string]interface{}, error) {
	payload := make(map[string]interface{})

	agentID := a.cfg.Agent.ID
	if agentID == "" {
		agentID = a.cfg.AgentID
	}
	version := a.cfg.Agent.Version
	if version == "" {
		version = config.Version
	}

	// Agent info
	payload["agent"] = map[string]string{
		"id":      agentID,
		"version": version,
	}

	for _, m := range a.modules {
		data, err := m.Gather()
		if err != nil {
			log.Printf("Module %s failed: %v", m.Name(), err)
			continue
		}

		// Special handling for modules that return multiple top-level keys
		if m.Name() == "host_os" {
			if mData, ok := data.(map[string]interface{}); ok {
				for k, v := range mData {
					payload[k] = v
				}
			}
		} else {
			payload[m.Name()] = data
		}
	}

	// Attach latest detected host vulnerabilities and misconfigurations
	if findings := a.detectorMgr.LastFindings(); len(findings) > 0 {
		payload["vulnerabilities"] = findings
	}

	return payload, nil
}
