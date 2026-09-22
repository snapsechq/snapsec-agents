package vulnscan

import (
	"context"
)

type ScanType string

type ScanJob struct {
	ID      string            `json:"id"`
	Tool    string            `json:"tool"`
	Targets []string          `json:"targets"`
	Options map[string]string `json:"options"`
}

type ScanResult struct {
	JobID    string              `json:"job_id"`
	Findings []NormalizedFinding `json:"findings"`
	Error    string              `json:"error,omitempty"`
}

type NormalizedFinding struct {
	FindingID     string                 `json:"finding_id"`
	Scanner       string                 `json:"scanner"`
	Category      string                 `json:"category"`
	Title         string                 `json:"title"`
	Severity      string                 `json:"severity"`
	Description   string                 `json:"description"`
	Evidence      string                 `json:"evidence"`
	Remediation   string                 `json:"remediation"`
	References    []string               `json:"references"`
	CVEs          []string               `json:"cves"`
	CWEs          []string               `json:"cwes"`
	AffectedAsset string                 `json:"affected_asset"`
	Metadata      map[string]interface{} `json:"metadata"`
}

type PluginConfig struct {
	BinDir      string `json:"bin_dir"`
	TemplateDir string `json:"template_dir"`
}

type ScannerPlugin interface {
	Init(config PluginConfig) error
	Capabilities() []ScanType
	Execute(ctx context.Context, job ScanJob) (ScanResult, error)
	Normalize(rawOutput []byte) ([]NormalizedFinding, error)
	Cleanup() error
}
