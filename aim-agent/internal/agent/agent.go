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
	"snapsec-agent/internal/vulnscan"
	"snapsec-agent/internal/vulnscan/nuclei"
	"snapsec-agent/internal/vulnscan/trivy"
	"encoding/json"
	"context"
	"sync"
	"strings"
)

type Agent struct {
	cfg            *config.Config
	configPath     string
	api            *api.Client
	modules        []modules.Module
	stop           chan struct{}
	scanManager    *vulnscan.ScanManager
	KillHandler    func()
	UpdateHandler  func() error
	triggeredScans map[string]bool
}

func NewAgent(cfg *config.Config, configPath string) *Agent {
	agent := &Agent{
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
		stop:           make(chan struct{}),
		triggeredScans: make(map[string]bool),
	}
	
	// Initialize VulnScanManager
	pluginCfg := vulnscan.PluginConfig{
		BinDir:      "./bin",
		TemplateDir: "./templates",
	}
	
	agent.scanManager = vulnscan.NewScanManager(pluginCfg, func(findings []vulnscan.NormalizedFinding) {
		if len(findings) > 0 {
			if _, err := agent.api.SendVulnerabilities(agent.cfg.AgentID, findings); err != nil {
				log.Printf("Failed to send vulnerabilities: %v", err)
			}
		}
	})
	
	// Register Nuclei
	if err := agent.scanManager.RegisterPlugin("nuclei", &nuclei.NucleiScanner{}); err != nil {
		log.Printf("Failed to initialize nuclei plugin: %v", err)
	}

	// Register Trivy
	if err := agent.scanManager.RegisterPlugin("trivy", &trivy.TrivyScanner{}); err != nil {
		log.Printf("Failed to initialize trivy plugin: %v", err)
	}
	
	agent.scanManager.SetScanInterval(cfg.VulnScanInterval)
	agent.scanManager.UpdateTargets(cfg.IncludeDirs, cfg.ExcludeDirs)
	return agent
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

	a.scanManager.Start()

	// 2. Start Heartbeat and Results Reporting Loops
	hbTicker := time.NewTicker(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
	assetTicker := time.NewTicker(parseCollectionInterval(a.cfg.CollectionInterval))
	defer hbTicker.Stop()
	defer assetTicker.Stop()

	log.Printf("Heartbeat interval: %ds, Collection interval: %s", a.cfg.HeartbeatInterval, a.cfg.CollectionInterval)

	// 3. Initial Heartbeat to sync config and check for updates immediately
	if a.cfg.Debug {
		log.Println("[Debug] Sending initial heartbeat to backend...")
	}
	if resp, err := a.api.Heartbeat(a.cfg.AgentID, config.Version); err == nil {
		log.Println("Initial heartbeat sent successfully")
		if a.cfg.Debug {
			respJSON, _ := json.Marshal(resp)
			log.Printf("[Debug] Initial heartbeat response received: %s", string(respJSON))
		}
		if a.checkKill(resp) {
			return nil
		}
		if a.syncConfiguration(resp) {
			// Intervals might have changed, restart tickers
			hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
			assetTicker.Reset(parseCollectionInterval(a.cfg.CollectionInterval))
		}
	} else {
		log.Printf("Initial heartbeat failed: %v", err)
	}

	// 4. Initial Asset Push
	if a.cfg.ActiveIngestion && a.cfg.CollectOnStart {
		log.Println("Gathering and sending initial asset results...")
		if a.cfg.Debug {
			log.Println("[Debug] Gathering all assets for initial push...")
		}
		if payload, err := a.gatherAll(); err == nil {
			if a.cfg.Debug {
				log.Println("[Debug] Sending initial asset results to backend...")
			}
			if resp, err := a.api.SendResults(a.cfg.AgentID, payload); err != nil {
				log.Printf("Failed to send initial results: %v", err)
			} else {
				log.Println("Initial asset results sent successfully")
				if a.cfg.Debug {
					respJSON, _ := json.Marshal(resp)
					log.Printf("[Debug] Initial asset results response received: %s", string(respJSON))
				}
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
					assetTicker.Reset(parseCollectionInterval(a.cfg.CollectionInterval))
				}
			}
		} else {
			log.Printf("Failed to gather initial results: %v", err)
		}
	} else {
		log.Println("Skipping initial asset push (CollectOnStart is false or ActiveIngestion is false).")
	}

	for {
		select {
		case <-hbTicker.C:
			// Send Heartbeat
			if a.cfg.Debug {
				log.Println("[Debug] Sending heartbeat to backend...")
			}
			resp, err := a.api.Heartbeat(a.cfg.AgentID, config.Version)
			if err != nil {
				log.Printf("Heartbeat failed: %v", err)
			} else {
				log.Println("Heartbeat sent successfully")
				if a.cfg.Debug {
					respJSON, _ := json.Marshal(resp)
					log.Printf("[Debug] Heartbeat response received: %s", string(respJSON))
				}
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated. Heartbeat: %ds, Collection Interval: %s", a.cfg.HeartbeatInterval, a.cfg.CollectionInterval)
					hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
					assetTicker.Reset(parseCollectionInterval(a.cfg.CollectionInterval))
				}
			}

		case <-assetTicker.C:
			if !a.cfg.ActiveIngestion {
				log.Println("Active ingestion is disabled. Skipping asset push.")
				continue
			}
			// Gather and Send Results
			if a.cfg.Debug {
				log.Println("[Debug] Gathering all assets for scheduled push...")
			}
			results, err := a.gatherAll()
			if err != nil {
				log.Printf("Failed to gather results: %v", err)
				continue
			}

			if a.cfg.Debug {
				log.Println("[Debug] Sending scheduled asset results to backend...")
			}
			resp, err := a.api.SendResults(a.cfg.AgentID, results)
			if err != nil {
				log.Printf("Failed to send results: %v", err)
			} else {
				log.Println("Asset results sent successfully")
				if a.cfg.Debug {
					respJSON, _ := json.Marshal(resp)
					log.Printf("[Debug] Asset results response received: %s", string(respJSON))
				}
				if a.checkKill(resp) {
					return nil
				}
				if a.syncConfiguration(resp) {
					log.Printf("Configuration updated from results response. Heartbeat: %ds, Collection Interval: %s", a.cfg.HeartbeatInterval, a.cfg.CollectionInterval)
					hbTicker.Reset(time.Duration(a.cfg.HeartbeatInterval) * time.Second)
					assetTicker.Reset(parseCollectionInterval(a.cfg.CollectionInterval))
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
	a.scanManager.Stop()
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
	if resp.Configuration.VulnScanInterval > 0 && resp.Configuration.VulnScanInterval != a.cfg.VulnScanInterval {
		a.cfg.VulnScanInterval = resp.Configuration.VulnScanInterval
		a.scanManager.SetScanInterval(a.cfg.VulnScanInterval)
		changed = true
	}
	if resp.Configuration.CollectionInterval != "" && resp.Configuration.CollectionInterval != a.cfg.CollectionInterval {
		a.cfg.CollectionInterval = resp.Configuration.CollectionInterval
		changed = true
	}
	if resp.Configuration.ActiveIngestion != a.cfg.ActiveIngestion {
		a.cfg.ActiveIngestion = resp.Configuration.ActiveIngestion
		changed = true
	}
	if resp.Configuration.CollectOnStart != a.cfg.CollectOnStart {
		a.cfg.CollectOnStart = resp.Configuration.CollectOnStart
		changed = true
	}
	if len(resp.Configuration.CollectionCategories) > 0 && !stringSlicesEqual(resp.Configuration.CollectionCategories, a.cfg.CollectionCategories) {
		a.cfg.CollectionCategories = resp.Configuration.CollectionCategories
		changed = true
	}
	if len(resp.Configuration.ScanTargets.IncludeDirs) > 0 && (!stringSlicesEqual(resp.Configuration.ScanTargets.IncludeDirs, a.cfg.IncludeDirs) || !stringSlicesEqual(resp.Configuration.ScanTargets.ExcludeDirs, a.cfg.ExcludeDirs)) {
		a.cfg.IncludeDirs = resp.Configuration.ScanTargets.IncludeDirs
		a.cfg.ExcludeDirs = resp.Configuration.ScanTargets.ExcludeDirs
		a.scanManager.UpdateTargets(a.cfg.IncludeDirs, a.cfg.ExcludeDirs)
		changed = true
	}

	if changed {
		if err := config.SaveConfig(a.configPath, a.cfg); err != nil {
			log.Printf("Failed to save dynamic configuration: %v", err)
		}
	}

	// Trigger manual scan jobs if any
	if len(resp.Configuration.ScanJobs) > 0 {
		var jobs []vulnscan.ScanJob
		for _, rawJob := range resp.Configuration.ScanJobs {
			b, err := json.Marshal(rawJob)
			if err == nil {
				var job vulnscan.ScanJob
				if err := json.Unmarshal(b, &job); err == nil {
					jobs = append(jobs, job)
				}
			}
		}
		if len(jobs) > 0 {
			a.scanManager.RunJobs(jobs)
		}
	}

	// Trigger scheduled scans if any are pending or launched (in case of restart)
	for _, scan := range resp.Configuration.Scans {
		if (scan.Status == "pending" || scan.Status == "launched") && !a.triggeredScans[scan.ScanID] {
			a.triggeredScans[scan.ScanID] = true
			go a.executeScheduledScan(scan)
		}
	}

	// 2. Check for Software Updates
	if resp.Configuration.LatestVersion != "" && resp.Configuration.LatestVersion != config.Version {
		if a.cfg.Debug || config.Version == "dev" {
			log.Printf("[Debug] Skipping auto-update in debug/development mode (LatestVersion: %s, CurrentVersion: %s)", resp.Configuration.LatestVersion, config.Version)
			return changed
		}

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
		if !isModuleEnabled(m.Name(), a.cfg.CollectionCategories) {
			if a.cfg.Debug {
				log.Printf("[Debug] Skipping disabled module: %s", m.Name())
			}
			continue
		}
		if a.cfg.Debug {
			log.Printf("[Debug] Running module: %s...", m.Name())
		}
		startTime := time.Now()
		data, err := m.Gather()
		if err != nil {
			log.Printf("Module %s failed: %v", m.Name(), err)
			continue
		}
		if a.cfg.Debug {
			log.Printf("[Debug] Module %s completed in %v", m.Name(), time.Since(startTime))
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

// stringSlicesEqual checks if two string slices have identical contents.
func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func isModuleEnabled(moduleName string, categories []string) bool {
	if len(categories) == 0 {
		return true
	}

	var category string
	switch moduleName {
	case "packages":
		category = "installed_packages"
	case "processes":
		category = "running_processes"
	case "hardware", "devices":
		category = "host_hardware"
	case "network":
		category = "network"
	case "users", "security":
		category = "users_and_access"
	case "host_os", "host":
		return true
	default:
		return true
	}

	for _, cat := range categories {
		if cat == category {
			return true
		}
	}
	return false
}

func (a *Agent) executeScheduledScan(scan api.ScanJobConfig) {
	log.Printf("Executing scheduled scan %s", scan.ScanID)
	
	if _, err := a.api.UpdateScanStatus(a.cfg.AgentID, scan.ScanID, "launched", ""); err != nil {
		log.Printf("Failed to report scan status as launched: %v", err)
	}

	plugins := a.scanManager.GetPlugins()
	if len(plugins) == 0 {
		log.Printf("No plugins registered for scheduled scan %s", scan.ScanID)
		_, err := a.api.UpdateScanStatus(a.cfg.AgentID, scan.ScanID, "failed", "No plugins registered")
		if err != nil {
			log.Printf("Failed to report scan failure: %v", err)
		}
		return
	}

	targets := scan.Targets
	if len(targets) == 0 {
		targets = a.cfg.IncludeDirs
	}
	if len(targets) == 0 {
		if runtime.GOOS == "windows" {
			targets = []string{"C:\\"}
		} else {
			targets = []string{"/"}
		}
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var allFindings []vulnscan.NormalizedFinding
	var scanErrors []string

	for name, plugin := range plugins {
		wg.Add(1)
		go func(toolName string, p vulnscan.ScannerPlugin) {
			defer wg.Done()
			
			// Copy options to avoid concurrent map access issues
			options := make(map[string]string)
			for k, v := range scan.Options {
				options[k] = v
			}
			if _, ok := options["excludes"]; !ok && len(a.cfg.ExcludeDirs) > 0 {
				options["excludes"] = strings.Join(a.cfg.ExcludeDirs, ",")
			}
			// If protocol or tags are missing, provide default values
			if _, ok := options["protocol"]; !ok {
				options["protocol"] = "file"
			}
			if _, ok := options["tags"]; !ok {
				options["tags"] = "secrets,keys,tokens,credentials,misconfiguration"
			}

			job := vulnscan.ScanJob{
				ID:      scan.ScanID + "-" + toolName,
				Tool:    toolName,
				Targets: targets,
				Options: options,
			}

			log.Printf("Running plugin %s for scheduled scan %s", toolName, scan.ScanID)
			ctx := context.Background()
			result, err := p.Execute(ctx, job)
			
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				log.Printf("Plugin %s failed for scheduled scan %s: %v", toolName, scan.ScanID, err)
				scanErrors = append(scanErrors, fmt.Sprintf("%s: %v", toolName, err))
				return
			}
			
			log.Printf("Plugin %s completed for scheduled scan %s with %d findings", toolName, scan.ScanID, len(result.Findings))
			allFindings = append(allFindings, result.Findings...)
		}(name, plugin)
	}

	wg.Wait()

	if len(allFindings) > 0 {
		if _, sErr := a.api.SendVulnerabilities(a.cfg.AgentID, allFindings); sErr != nil {
			log.Printf("Failed to send vulnerabilities: %v", sErr)
		}
	}

	// Update final status
	if len(scanErrors) == len(plugins) {
		// All plugins failed
		errMsg := strings.Join(scanErrors, "; ")
		_, rErr := a.api.UpdateScanStatus(a.cfg.AgentID, scan.ScanID, "failed", errMsg)
		if rErr != nil {
			log.Printf("Failed to report scan failure: %v", rErr)
		}
	} else {
		// At least one plugin succeeded
		var statusComment string
		if len(scanErrors) > 0 {
			statusComment = fmt.Sprintf("Completed with partial errors: %s", strings.Join(scanErrors, "; "))
		}
		_, rErr := a.api.UpdateScanStatus(a.cfg.AgentID, scan.ScanID, "completed", statusComment)
		if rErr != nil {
			log.Printf("Failed to report scan completion: %v", rErr)
		}
	}
}

func parseCollectionInterval(intervalStr string) time.Duration {
	if len(intervalStr) < 2 {
		log.Printf("Invalid collection_interval '%s', falling back to 30m", intervalStr)
		return 30 * time.Minute
	}
	unit := intervalStr[len(intervalStr)-1:]
	if unit != "s" && unit != "m" && unit != "h" {
		log.Printf("Unsupported collection_interval unit in '%s' (only s, m, h are supported), falling back to 30m", intervalStr)
		return 30 * time.Minute
	}

	d, err := time.ParseDuration(intervalStr)
	if err != nil {
		log.Printf("Failed to parse collection_interval '%s', falling back to 30m: %v", intervalStr, err)
		return 30 * time.Minute
	}
	return d
}
