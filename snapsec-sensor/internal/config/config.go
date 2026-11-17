package config

import (
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

var Version = "4.0.3" // Overridden by ldflags during build

type AgentSection struct {
	ID            string `yaml:"id,omitempty"`
	AgentID       string `yaml:"agent_id,omitempty"`
	Enabled       bool   `yaml:"enabled"`
	Version       string `yaml:"version"`
	UpdateChannel string `yaml:"update_channel"`
}

type InventorySection struct {
	Enabled  bool `yaml:"enabled"`
	Interval int  `yaml:"interval"` // in seconds
}

type VulnerabilityScanningSection struct {
	Enabled  bool `yaml:"enabled"`
	Interval int  `yaml:"interval"` // in seconds
}

type CommunicationSection struct {
	BackendURL        string `yaml:"backend_url"`
	AssetUpstream     string `yaml:"asset_upstream,omitempty"`
	IssuesUpstream    string `yaml:"issues_upstream,omitempty"`
	APIKey            string `yaml:"api_key"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"` // in seconds
}

type Config struct {
	Agent                 AgentSection                 `yaml:"agent"`
	Inventory             InventorySection             `yaml:"inventory"`
	VulnerabilityScanning VulnerabilityScanningSection `yaml:"vulnerability_scanning"`
	Communication         CommunicationSection         `yaml:"communication"`

	// Flat/legacy fields for backward compatibility
	BackendURL        string `yaml:"backend_url,omitempty"`
	AssetUpstream     string `yaml:"asset_upstream,omitempty"`
	IssuesUpstream    string `yaml:"issues_upstream,omitempty"`
	APIKey            string `yaml:"api_key,omitempty"`
	AgentID           string `yaml:"agent_id,omitempty"`
	Interval          int    `yaml:"interval,omitempty"`
	HeartbeatInterval int    `yaml:"heartbeat_interval,omitempty"`
	AssetPushInterval int    `yaml:"asset_push_interval,omitempty"`
}

func GetDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\snapsec.d\\snapsec-sensor.yaml"
	}
	return "/etc/snapsec.d/snapsec-sensor.yaml"
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw map[string]interface{}
	_ = yaml.Unmarshal(data, &raw)

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	// Migrate flat fields to Communication
	if cfg.Communication.BackendURL == "" && cfg.BackendURL != "" {
		cfg.Communication.BackendURL = cfg.BackendURL
	}
	if cfg.Communication.AssetUpstream == "" && cfg.AssetUpstream != "" {
		cfg.Communication.AssetUpstream = cfg.AssetUpstream
	}
	if cfg.Communication.IssuesUpstream == "" && cfg.IssuesUpstream != "" {
		cfg.Communication.IssuesUpstream = cfg.IssuesUpstream
	}
	if cfg.Communication.APIKey == "" && cfg.APIKey != "" {
		cfg.Communication.APIKey = cfg.APIKey
	}

	// Migrate flat fields to Agent
	if cfg.Agent.ID == "" {
		if cfg.Agent.AgentID != "" {
			cfg.Agent.ID = cfg.Agent.AgentID
		} else if cfg.AgentID != "" {
			cfg.Agent.ID = cfg.AgentID
		}
	}
	if cfg.Agent.Version == "" {
		cfg.Agent.Version = Version
	}
	if cfg.Agent.UpdateChannel == "" {
		cfg.Agent.UpdateChannel = "stable"
	}

	// Determine defaults for Agent.Enabled (default true unless explicitly false in raw)
	agentEnabledExplicit := false
	if raw != nil {
		if agentRaw, ok := raw["agent"].(map[string]interface{}); ok {
			if _, hasEnabled := agentRaw["enabled"]; hasEnabled {
				agentEnabledExplicit = true
			}
		}
	}
	if !agentEnabledExplicit && raw != nil {
		cfg.Agent.Enabled = true
	}

	// Determine defaults for Inventory.Enabled (default true unless explicitly false in raw)
	inventoryEnabledExplicit := false
	if raw != nil {
		if invRaw, ok := raw["inventory"].(map[string]interface{}); ok {
			if _, hasEnabled := invRaw["enabled"]; hasEnabled {
				inventoryEnabledExplicit = true
			}
		}
	}
	if !inventoryEnabledExplicit && raw != nil {
		cfg.Inventory.Enabled = true
	}

	// Determine defaults for VulnerabilityScanning.Enabled:
	// Default is FALSE (only enabled via vuln upstream heartbeat)
	vulnEnabledExplicit := false
	if raw != nil {
		if vulnRaw, ok := raw["vulnerability_scanning"].(map[string]interface{}); ok {
			if _, hasEnabled := vulnRaw["enabled"]; hasEnabled {
				vulnEnabledExplicit = true
			}
		}
	}
	if !vulnEnabledExplicit {
		cfg.VulnerabilityScanning.Enabled = false
	}

	// Intervals
	if cfg.Communication.HeartbeatInterval == 0 {
		if cfg.HeartbeatInterval > 0 {
			cfg.Communication.HeartbeatInterval = cfg.HeartbeatInterval
		} else if cfg.Interval > 0 {
			cfg.Communication.HeartbeatInterval = cfg.Interval
		} else {
			cfg.Communication.HeartbeatInterval = 60
		}
	}

	if cfg.Inventory.Interval == 0 {
		if cfg.AssetPushInterval > 0 {
			cfg.Inventory.Interval = cfg.AssetPushInterval
		} else if cfg.Interval > 0 {
			cfg.Inventory.Interval = cfg.Interval
		} else {
			cfg.Inventory.Interval = 300
		}
	}

	if cfg.VulnerabilityScanning.Interval == 0 {
		cfg.VulnerabilityScanning.Interval = 3600
	}

	// Sync flat fields with sections so legacy callers reading flat fields continue to work
	cfg.BackendURL = cfg.Communication.BackendURL
	cfg.AssetUpstream = cfg.Communication.AssetUpstream
	cfg.IssuesUpstream = cfg.Communication.IssuesUpstream
	cfg.APIKey = cfg.Communication.APIKey
	cfg.AgentID = cfg.Agent.ID
	cfg.Agent.AgentID = cfg.Agent.ID
	cfg.HeartbeatInterval = cfg.Communication.HeartbeatInterval
	cfg.AssetPushInterval = cfg.Inventory.Interval

	return &cfg, nil
}

type DiskConfig struct {
	Agent                 AgentSection                 `yaml:"agent"`
	Inventory             InventorySection             `yaml:"inventory"`
	VulnerabilityScanning VulnerabilityScanningSection `yaml:"vulnerability_scanning"`
	Communication         CommunicationSection         `yaml:"communication"`
}

func SaveConfig(path string, cfg *Config) error {
	if cfg.Agent.ID == "" && cfg.AgentID != "" {
		cfg.Agent.ID = cfg.AgentID
	}
	cfg.Agent.AgentID = ""
	cfg.AgentID = cfg.Agent.ID

	if cfg.Communication.BackendURL == "" && cfg.BackendURL != "" {
		cfg.Communication.BackendURL = cfg.BackendURL
	}
	if cfg.Communication.AssetUpstream == "" && cfg.AssetUpstream != "" {
		cfg.Communication.AssetUpstream = cfg.AssetUpstream
	}
	if cfg.Communication.IssuesUpstream == "" && cfg.IssuesUpstream != "" {
		cfg.Communication.IssuesUpstream = cfg.IssuesUpstream
	}
	if cfg.Communication.APIKey == "" && cfg.APIKey != "" {
		cfg.Communication.APIKey = cfg.APIKey
	}
	if cfg.Communication.HeartbeatInterval == 0 && cfg.HeartbeatInterval > 0 {
		cfg.Communication.HeartbeatInterval = cfg.HeartbeatInterval
	}
	if cfg.Inventory.Interval == 0 && cfg.AssetPushInterval > 0 {
		cfg.Inventory.Interval = cfg.AssetPushInterval
	}

	diskCfg := DiskConfig{
		Agent:                 cfg.Agent,
		Inventory:             cfg.Inventory,
		VulnerabilityScanning: cfg.VulnerabilityScanning,
		Communication:         cfg.Communication,
	}

	data, err := yaml.Marshal(&diskCfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
