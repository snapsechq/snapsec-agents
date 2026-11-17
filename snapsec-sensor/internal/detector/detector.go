package detector

import (
	"context"
	"log"
	"strings"
	"sync"
)

type Manager struct {
	mu           sync.Mutex
	scanning     bool
	detectors    []Detector
	lastFindings []Finding
}

func NewManager(configPath ...string) *Manager {
	m := &Manager{
		detectors:    make([]Detector, 0),
		lastFindings: make([]Finding, 0),
	}

	// Register the built-in host security detectors
	m.RegisterDetector(NewHardeningDetector())
	m.RegisterDetector(NewConfigIssuesDetector())
	m.RegisterDetector(NewPrivEscDetector())
	m.RegisterDetector(NewVulnerabilitiesDetector())

	return m
}

// RegisterDetector adds a detector module to the manager
func (m *Manager) RegisterDetector(d Detector) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.detectors = append(m.detectors, d)
}

// GetDetectors returns the list of registered detectors
func (m *Manager) GetDetectors() []Detector {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]Detector, len(m.detectors))
	copy(copied, m.detectors)
	return copied
}

// LastFindings returns a copy of the most recently detected findings
func (m *Manager) LastFindings() []Finding {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]Finding, len(m.lastFindings))
	copy(copied, m.lastFindings)
	return copied
}

// RunAll executes all registered detector modules and returns aggregated findings
func (m *Manager) RunAll(ctx context.Context) ([]Finding, error) {
	m.mu.Lock()
	if m.scanning {
		m.mu.Unlock()
		log.Println("[DetectorManager] Scan already in progress, returning cached findings")
		return m.LastFindings(), nil
	}
	m.scanning = true
	detectors := make([]Detector, len(m.detectors))
	copy(detectors, m.detectors)
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.scanning = false
		m.mu.Unlock()
	}()

	log.Printf("[DetectorManager] Running %d host detector modules...", len(detectors))
	var aggregated []Finding

	for _, d := range detectors {
		select {
		case <-ctx.Done():
			return aggregated, ctx.Err()
		default:
		}

		log.Printf("[DetectorManager] Executing detector: %s (%s)", d.Name(), d.Category())
		findings, err := d.Run(ctx)
		if err != nil {
			log.Printf("[DetectorManager] Detector %s encountered an error: %v", d.Name(), err)
			continue
		}
		// Ensure VulnType is populated on all findings
		for i := range findings {
			if findings[i].VulnType == "" {
				switch findings[i].Category {
				case CategoryHardening, CategoryConfiguration:
					findings[i].VulnType = VulnTypeConfiguration
				default:
					findings[i].VulnType = GetHostOSVulnType()
				}
			}
		}
		log.Printf("[DetectorManager] Detector %s produced %d findings", d.Name(), len(findings))
		aggregated = append(aggregated, findings...)
	}

	m.mu.Lock()
	m.lastFindings = aggregated
	m.mu.Unlock()

	log.Printf("[DetectorManager] All detectors finished. Total findings: %d", len(aggregated))
	return aggregated, nil
}

// RunCategory executes all detectors belonging to a specific category
func (m *Manager) RunCategory(ctx context.Context, category string) ([]Finding, error) {
	detectors := m.GetDetectors()
	var aggregated []Finding

	for _, d := range detectors {
		if strings.EqualFold(d.Category(), category) {
			findings, err := d.Run(ctx)
			if err != nil {
				log.Printf("[DetectorManager] Detector %s error: %v", d.Name(), err)
				continue
			}
			for i := range findings {
				if findings[i].VulnType == "" {
					switch findings[i].Category {
					case CategoryHardening, CategoryConfiguration:
						findings[i].VulnType = VulnTypeConfiguration
					default:
						findings[i].VulnType = GetHostOSVulnType()
					}
				}
			}
			aggregated = append(aggregated, findings...)
		}
	}

	return aggregated, nil
}

// RunScan triggers all internal detector modules
func (m *Manager) RunScan() error {
	_, err := m.RunAll(context.Background())
	return err
}
