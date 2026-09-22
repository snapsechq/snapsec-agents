package service

import (
	"log"
	"fmt"
	"os"
	"snapsec-agent/internal/agent"
	"snapsec-agent/internal/config"

	"github.com/kardianos/service"
)

type program struct {
	agent *agent.Agent
}

func (p *program) Start(s service.Service) error {
	// Start should not block. Do the actual work in a separate goroutine.
	go p.run()
	return nil
}

func (p *program) run() {
	if err := p.agent.Start(); err != nil {
		log.Printf("Agent error: %v", err)
	}
}

func (p *program) Stop(s service.Service) error {
	p.agent.Stop()
	return nil
}

func newService(cfg *config.Config, configPath string) (service.Service, error) {
	svcConfig := &service.Config{
		Name:        "snapsec-agent",
		DisplayName: "Snapsec Agent",
		Description: "Monitors system assets and sends data to Snapsec backend.",
	}

	a := agent.NewAgent(cfg, configPath)
	prg := &program{agent: a}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		return nil, err
	}

	a.KillHandler = func() {
		log.Println("Kill signal received. Uninstalling service...")
		if err := s.Uninstall(); err != nil {
			log.Printf("Failed to uninstall service: %v", err)
		}
		log.Println("Service uninstalled. Exiting.")
		os.Exit(0)
	}

	a.UpdateHandler = func() error {
		log.Println("Restart signal received from updater. Restarting service...")
		return s.Restart()
	}

	return s, nil
}

func AutoHandle(cfg *config.Config, configPath string, foreground bool) error {
	s, err := newService(cfg, configPath)
	if err != nil {
		return err
	}

	// Check if we are running interactively or as a service
	if service.Interactive() {
		if foreground {
			return s.Run()
		}

		status, err := s.Status()
		
		// 1. Ensure/Update registration with backend
		a := agent.NewAgent(cfg, configPath)
		log.Println("Registering agent with backend...")
		if err := a.RegisterOnly(); err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}

		// 2. Install as service if not present
		if err != nil || status == service.StatusUnknown {
			log.Println("Installing service...")
			if err := s.Install(); err != nil {
				log.Printf("Service installation warning: %v", err)
			}
		}

		// 3. Handle service starting/restarting
		if status == service.StatusRunning {
			log.Println("Agent already running as a service. Restarting to apply changes...")
			if err := s.Restart(); err != nil {
				return fmt.Errorf("failed to restart service: %w", err)
			}
			log.Println("Snapsec Agent service restarted successfully.")
		} else {
			log.Println("Starting agent service...")
			if err := s.Start(); err != nil {
				// Fallback to restart if start fails (e.g. status was cached)
				if err := s.Restart(); err != nil {
					return fmt.Errorf("failed to start agent service: %w", err)
				}
			}
			log.Println("Snapsec Agent service started successfully.")
		}

		log.Println("Installation/Update complete. Agent is running in the background.")
		return nil
	}

	return s.Run()
}

