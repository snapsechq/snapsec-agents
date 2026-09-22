package vulnscan

import (
	"context"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

type ScanManager struct {
	plugins       map[string]ScannerPlugin
	config        PluginConfig
	scanInterval  time.Duration
	stopCh        chan struct{}
	wg            sync.WaitGroup
	resultHandler func([]NormalizedFinding)
	includes      []string
	excludes      []string
}

func NewScanManager(config PluginConfig, handler func([]NormalizedFinding)) *ScanManager {
	return &ScanManager{
		plugins:       make(map[string]ScannerPlugin),
		config:        config,
		stopCh:        make(chan struct{}),
		resultHandler: handler,
	}
}

func (m *ScanManager) RegisterPlugin(name string, plugin ScannerPlugin) error {
	if err := plugin.Init(m.config); err != nil {
		return err
	}
	m.plugins[name] = plugin
	return nil
}

func (m *ScanManager) GetPlugin(name string) (ScannerPlugin, bool) {
	plugin, ok := m.plugins[name]
	return plugin, ok
}

func (m *ScanManager) GetPlugins() map[string]ScannerPlugin {
	copyMap := make(map[string]ScannerPlugin)
	for k, v := range m.plugins {
		copyMap[k] = v
	}
	return copyMap
}

func (m *ScanManager) UpdateTargets(includes []string, excludes []string) {
	m.includes = includes
	m.excludes = excludes
}

func (m *ScanManager) SetScanInterval(intervalSeconds int) {
	if intervalSeconds > 0 {
		m.scanInterval = time.Duration(intervalSeconds) * time.Second
	} else {
		m.scanInterval = 0
	}
}

func (m *ScanManager) Start() {
	m.wg.Add(1)
	go m.runLoop()
}

func (m *ScanManager) Stop() {
	close(m.stopCh)
	m.wg.Wait()
	for _, plugin := range m.plugins {
		plugin.Cleanup()
	}
}

func (m *ScanManager) runLoop() {
	defer m.wg.Done()
	
	if m.scanInterval <= 0 {
		return
	}
	
	ticker := time.NewTicker(m.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.RunScheduledScan()
		case <-m.stopCh:
			return
		}
	}
}

func (m *ScanManager) RunScheduledScan() {
	log.Println("Starting scheduled vulnerability scan...")
	
	targets := m.includes
	excludes := m.excludes
	
	if len(targets) == 0 {
		if runtime.GOOS == "windows" {
			targets = []string{"C:\\"}
		} else {
			targets = []string{"/"}
		}
	}

	for name, plugin := range m.plugins {
		job := ScanJob{
			ID:      "scheduled-" + name + "-" + time.Now().Format("20060102150405"),
			Tool:    name,
			Targets: targets,
			Options: map[string]string{
				"protocol": "file",
				"tags":     "secrets,keys,tokens,credentials,misconfiguration",
			},
		}
		
		if len(excludes) > 0 {
			job.Options["excludes"] = strings.Join(excludes, ",")
		}
		
		go m.RunJob(plugin, job)
	}
}

func (m *ScanManager) RunJobs(jobs []ScanJob) {
	for _, job := range jobs {
		plugin, ok := m.plugins[job.Tool]
		if !ok {
			log.Printf("Cannot run job %s: Tool %s not registered", job.ID, job.Tool)
			continue
		}
		go m.RunJob(plugin, job)
	}
}

func (m *ScanManager) RunJob(plugin ScannerPlugin, job ScanJob) {
	ctx := context.Background()

	log.Printf("Executing scan job %s with tool %s", job.ID, job.Tool)
	result, err := plugin.Execute(ctx, job)
	if err != nil {
		log.Printf("Scan job %s failed: %v", job.ID, err)
		return
	}

	log.Printf("Scan job %s completed with %d findings", job.ID, len(result.Findings))
	if m.resultHandler != nil {
		m.resultHandler(result.Findings)
	}
}

func (m *ScanManager) RunCLI(tool string, target string, resume string) {
	var targets []string
	var excludes []string
	if target == "" {
		targets = m.includes
		excludes = m.excludes
		if len(targets) == 0 {
			if runtime.GOOS == "windows" {
				targets = []string{"C:\\"}
			} else {
				targets = []string{"/"}
			}
		}
	} else {
		targets = []string{target}
	}

	for name, plugin := range m.plugins {
		if tool != "" && name != tool {
			continue
		}

		job := ScanJob{
			ID:      "cli-" + name + "-" + time.Now().Format("20060102150405"),
			Tool:    name,
			Targets: targets,
			Options: map[string]string{
				"protocol": "file",
				"tags":     "secrets,keys,tokens,credentials,misconfiguration",
				"verbose":  "true",
			},
		}

		if resume != "" {
			job.Options["resume"] = resume
		}

		if len(excludes) > 0 {
			job.Options["excludes"] = strings.Join(excludes, ",")
		}

		// Run synchronously for CLI
		m.wg.Add(1)
		func() {
			defer m.wg.Done()
			m.RunJob(plugin, job)
		}()
	}
}
