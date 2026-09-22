package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"snapsec-agent/internal/config"
	"snapsec-agent/internal/cpulimit"
	"snapsec-agent/internal/service"
	"snapsec-agent/internal/vulnscan"
	"snapsec-agent/internal/vulnscan/nuclei"
	"snapsec-agent/internal/vulnscan/trivy"
	"snapsec-agent/pkg/api"
)

func main() {
	if err := cpulimit.Apply(); err != nil {
		log.Printf("Warning: failed to apply CPU limits: %v", err)
	}

	if len(os.Args) > 1 && os.Args[1] == "scan" {
		scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)
		toolFlag := scanCmd.String("tool", "", "Specific tool to run (e.g., nuclei)")
		outputFlag := scanCmd.String("output", "", "Output file for JSON results")
		targetFlag := scanCmd.String("target", "", "Target to scan (e.g. /etc, C:\\, or example.com)")
		resumeFlag := scanCmd.String("resume", "", "Path to Nuclei resume.cfg to continue a crashed scan")
		configPath := scanCmd.String("config", config.GetDefaultConfigPath(), "Path to configuration file")

		scanCmd.Parse(os.Args[2:])

		cfg, err := config.LoadConfig(*configPath)
		if err != nil {
			log.Fatalf("Error loading config: %v", err)
		}

		apiClient := api.NewClient(cfg.BackendURL, cfg.APIKey)

		pluginCfg := vulnscan.PluginConfig{
			BinDir:      "./bin",
			TemplateDir: "./templates",
		}

		manager := vulnscan.NewScanManager(pluginCfg, func(findings []vulnscan.NormalizedFinding) {
			if *outputFlag != "" {
				b, _ := json.MarshalIndent(findings, "", "  ")
				if err := os.WriteFile(*outputFlag, b, 0644); err != nil {
					log.Printf("Failed to write output file: %v", err)
				} else {
					log.Printf("Results written to %s", *outputFlag)
				}
			} else {
				if cfg.AgentID == "" {
					log.Println("AgentID not set, cannot send to AIM. Please register the agent first.")
					return
				}
				if _, err := apiClient.SendVulnerabilities(cfg.AgentID, findings); err != nil {
					log.Printf("Failed to send vulnerabilities to AIM: %v", err)
				} else {
					log.Println("Results successfully sent to AIM.")
				}
			}
		})

		if err := manager.RegisterPlugin("nuclei", &nuclei.NucleiScanner{}); err != nil {
			log.Fatalf("Failed to initialize nuclei plugin: %v", err)
		}

		if err := manager.RegisterPlugin("trivy", &trivy.TrivyScanner{}); err != nil {
			log.Fatalf("Failed to initialize trivy plugin: %v", err)
		}

		manager.RunCLI(*toolFlag, *targetFlag, *resumeFlag)
		manager.Stop()
		return
	}

	configPath := flag.String("config", config.GetDefaultConfigPath(), "Path to configuration file")
	foreground := flag.Bool("f", false, "Run in foreground (interactive mode)")
	flag.BoolVar(foreground, "foreground", false, "Run in foreground (interactive mode)")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)

	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		fmt.Printf("Please ensure config exists at %s or specify path with -config\n", *configPath)
		os.Exit(1)
	}

	if *debug {
		cfg.Debug = true
	}

	log.Printf("Successfully loaded config from %s: BackendURL=%s, APIKey=%s, AgentID=%s, HeartbeatInterval=%ds, CollectionInterval=%s, VulnScanInterval=%ds",
		*configPath, cfg.BackendURL, cfg.APIKey, cfg.AgentID, cfg.HeartbeatInterval, cfg.CollectionInterval, cfg.VulnScanInterval)


	// AutoHandle will install/register if not installed, or run if already installed.
	if err := service.AutoHandle(cfg, *configPath, *foreground); err != nil {
		log.Fatal(err)
	}
}
