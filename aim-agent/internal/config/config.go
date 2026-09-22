package config

import (
	"os"
	"runtime"

	"gopkg.in/yaml.v3"
)

var Version = "dev" // Overridden by ldflags during build

type Config struct {
	BackendURL        string `yaml:"backend_url"`
	APIKey            string `yaml:"api_key"`
	AgentID           string `yaml:"agent_id,omitempty"`
	HeartbeatInterval int    `yaml:"heartbeat_interval"` // in seconds
	AssetPushInterval int    `yaml:"asset_push_interval"` // in seconds
}

func GetDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return "C:\\ProgramData\\snapsec-agent\\config.yaml"
	}
	return "/etc/snapsec-agent.yaml"
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 900 // Default to 15 minutes
	}

	if cfg.AssetPushInterval == 0 {
		cfg.AssetPushInterval = 1800 // Default to 30 minutes
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
