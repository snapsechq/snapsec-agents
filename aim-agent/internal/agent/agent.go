package agent

import (
	"fmt"
	"log"
	"os"
	"snapsec-agent/internal/config"
	"snapsec-agent/internal/modules"
	"snapsec-agent/internal/modules/devices"
	"snapsec-agent/internal/modules/hardware"
	"snapsec-agent/internal/modules/host"
	"snapsec-agent/internal/modules/network"
	"snapsec-agent/internal/modules/packages"
	"snapsec-agent/internal/modules/processes"
	"snapsec-agent/internal/modules/security"
	"snapsec-agent/internal/modules/services"
	"snapsec-agent/internal/modules/users"
	"snapsec-agent/internal/modules/classification"
	"snapsec-agent/pkg/api"
	"time"
	"runtime"
	"snapsec-agent/internal/updater"
)

type Agent struct {
	cfg         *config.Config
	configPath  string
	api         *api.Client
	modules     []modules.Module
	stop        chan struct{}
	KillHandler func()
	UpdateHandler func() error
}

func NewAgent(cfg *config.Config, configPath string) *Agent {
	return &Agent{
		cfg:        cfg,
		configPath: configPath,
		api:        api.NewClient(cfg.BackendURL, cfg.APIKey),
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
		stop: make(chan struct{}),
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
			// Find first non-loopback IPv4
			for _, i := range n.Interfaces {
				if i.Name != "lo" && len(i.IPv4) > 0 {
					ipAddress = i.IPv4[0]
					break
				}
			}
		}
	}

	// Determine architecture (Normalized OS)
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
	// Handle common aliases if necessary (e.g., from uname -m style to go style)
	// But runtime.GOARCH is already what we want for release filenames usually.

	log.Printf("Registering agent with hostname: %s, os: %s, architecture: %s, arch: %s, ip: %s", hostname, osName, architecture, arch, ipAddress)

	// Gather the full inventory so the backend can create the workstation/server
	// (and technology) assets immediately on registration, rather than waiting
	// for the first scheduled asset push. Best-effort: register even if it fails.
	inventory, gErr := a.gatherAll()
	if gErr != nil {
		log.Printf("Failed to gather inventory for registration: %v", gErr)
		inventory = nil
	}

	agentID, err := a.api.Register(hostname, osName, config.Version, ipAddress, architecture, arch, inventory)
	if err != nil {
		return err
	}

	log.Printf("Registration successful. Assigned Agent ID: %s", agentID)
	a.cfg.AgentID = agentID

	// Save the agent ID back to the config file
	if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
		return fmt.Errorf("failed to save config with agent ID: %w", err)
	}

	return nil
}

func (a *Agent) Start() error {
	log.Println("Starting Snapsec Agent...")

	// 1. Ensure we have an Agent ID
	if a.cfg.AgentID == "" {
		if err := a.RegisterOnly(); err != nil {
			return fmt.Errorf("failed to register during start: %w", err)
		}
	}

	// 2. Start Heartbeat and Results Reporting Loops
	hbTicker := time.NewTicker(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
	assetTicker := time.NewTicker(time.Duration(a.cfg.AssetPushInterval) * time.Second)
	defer hbTicker.Stop()
	defer assetTicker.Stop()

	log.Printf("Heartbeat interval: %ds, Asset push interval: %ds", a.cfg.HeartbeatInterval, a.cfg.AssetPushInterval)

	// 3. Initial Heartbeat to sync config and check for updates immediately
	if resp, err := a.api.Heartbeat(a.cfg.AgentID, config.Version); err == nil {
		if a.checkKill(resp) {
			return nil
		}
		if a.syncConfiguration(resp) {
			// Intervals might have changed, restart tickers
			hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
			assetTicker.Reset(time.Duration(a.cfg.AssetPushInterval) * time.Second)
		}
	}

	// 4. Initial Asset Push
	// Send immediate asset results so we don't wait for the first scheduled asset push ticker.
	log.Println("Gathering and sending initial asset results...")
	if payload, err := a.gatherAll(); err == nil {
		if resp, err := a.api.SendResults(a.cfg.AgentID, payload); err != nil {
			log.Printf("Failed to send initial results: %v", err)
		} else {
			if a.checkKill(resp) {
				return nil
			}
			if a.syncConfiguration(resp) {
				hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
				assetTicker.Reset(time.Duration(a.cfg.AssetPushInterval) * time.Second)
			}
		}
	} else {
		log.Printf("Failed to gather initial results: %v", err)
	}

	for {
		select {
		case <-hbTicker.C:
			// Send Heartbeat
			resp, err := a.api.Heartbeat(a.cfg.AgentID, config.Version)
			if err != nil {
				log.Printf("Heartbeat failed: %v", err)
			} else {
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated. Heartbeat: %ds, Asset Push: %ds", a.cfg.HeartbeatInterval, a.cfg.AssetPushInterval)
					hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
					assetTicker.Reset(time.Duration(a.cfg.AssetPushInterval) * time.Second)
				}
			}

		case <-assetTicker.C:
			// Gather and Send Results
			results, err := a.gatherAll()
			if err != nil {
				log.Printf("Failed to gather results: %v", err)
				continue
			}

			resp, err := a.api.SendResults(a.cfg.AgentID, results)
			if err != nil {
				log.Printf("Failed to send results: %v", err)
			} else {
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated from results response. Heartbeat: %ds, Asset Push: %ds", a.cfg.HeartbeatInterval, a.cfg.AssetPushInterval)
					hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
					assetTicker.Reset(time.Duration(a.cfg.AssetPushInterval) * time.Second)
				}
			}

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
	if resp.Configuration.HeartbeatInterval > 0 && resp.Configuration.HeartbeatInterval != a.cfg.HeartbeatInterval {
		a.cfg.HeartbeatInterval = resp.Configuration.HeartbeatInterval
		changed = true
	}
	if resp.Configuration.AssetPushInterval > 0 && resp.Configuration.AssetPushInterval != a.cfg.AssetPushInterval {
		a.cfg.AssetPushInterval = resp.Configuration.AssetPushInterval
		changed = true
	}

	if changed {
		if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
			log.Printf("Failed to save updated configuration: %v", err)
		}
	}

	// 2. Check for Software Updates
	if resp.Configuration.LatestVersion != "" && resp.Configuration.LatestVersion != config.Version {
		log.Printf("New version available: %s (current: %s). Starting auto-update...", resp.Configuration.LatestVersion, config.Version)
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

	// Agent info
	payload["agent"] = map[string]string{
		"id":      a.cfg.AgentID,
		"version": config.Version,
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

	return payload, nil
}
