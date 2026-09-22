package config

import (
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

var Version = "dev" // Overridden by ldflags during build

type Config struct {
	BackendURL           string   `yaml:"backend_url"`
	APIKey               string   `yaml:"api_key"`
	AgentID              string   `yaml:"agent_id,omitempty"`
	HeartbeatInterval    int      `yaml:"heartbeat_interval"` // in seconds
	VulnScanInterval     int      `yaml:"vuln_scan_interval"` // in seconds
	IncludeDirs          []string `yaml:"include_dirs,omitempty"`
	ExcludeDirs          []string `yaml:"exclude_dirs,omitempty"`
	ActiveIngestion      bool     `yaml:"active_ingestion"`
	CollectionCategories []string `yaml:"collection_categories,omitempty"`
	CollectionInterval   string   `yaml:"collection_interval,omitempty"`
	CollectOnStart       bool     `yaml:"collect_on_start"`
	Debug                bool     `yaml:"debug,omitempty"`
	ExplicitKeys         map[string]bool `yaml:"-"`
}

func GetDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\snapsec.d\\snapsec-detector.yaml"
	}
	return "/etc/snapsec.d/snapsec-detector.yaml"
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var rawMap map[string]interface{}
	if err := yaml.Unmarshal(data, &rawMap); err != nil {
		return nil, err
	}

	cfg := Config{
		ActiveIngestion:    true,
		CollectOnStart:     true,
		CollectionInterval: "30m",
		ExplicitKeys:       make(map[string]bool),
	}
	for k := range rawMap {
		cfg.ExplicitKeys[k] = true
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 900 // Default to 15 minutes
	}

	if cfg.VulnScanInterval == 0 {
		cfg.VulnScanInterval = 86400 // Default to 24 hours
	}

	return &cfg, nil
}

func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
