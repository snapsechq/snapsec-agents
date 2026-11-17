package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"snapsec-agent/internal/config"
	"snapsec-agent/internal/service"
)

func main() {
	configPath := flag.String("config", config.GetDefaultConfigPath(), "Path to configuration file")
	foreground := flag.Bool("f", false, "Run in foreground (interactive mode)")
	flag.BoolVar(foreground, "foreground", false, "Run in foreground (interactive mode)")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)

	if err != nil {
		fmt.Printf("Error loading config: %v\n", err)
		fmt.Printf("Please ensure config exists at %s or specify path with -config\n", *configPath)
		os.Exit(1)
	}

	// AutoHandle will install/register if not installed, or run if already installed.
	if err := service.AutoHandle(cfg, *configPath, *foreground); err != nil {
		log.Fatal(err)
	}
}

