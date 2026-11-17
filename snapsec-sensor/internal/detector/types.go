package detector

import (
	"context"
	"runtime"
	"time"
)

// Detector Categories
const (
	CategoryHardening           = "hardening"
	CategoryConfiguration       = "configuration"
	CategoryPrivilegeEscalation = "privilege_escalation"
	CategoryVulnerability       = "vulnerability"
)

// Supported Vulnerability Types matching the backend taxonomy (vulnerability.model.js)
const (
	// Penetration Testing (PTaaS)
	VulnTypeWeb               = "web"
	VulnTypeAPI               = "api"
	VulnTypeMobile            = "mobile"
	VulnTypeInfrastructure    = "infrastructure"
	VulnTypeNetwork           = "network"
	VulnTypeWireless          = "wireless"
	VulnTypeSocialEngineering = "social-engineering"
	VulnTypeRedTeam           = "red-team"

	// Vulnerability Scanning (VM & Host Agent)
	VulnTypeWindows    = "windows"
	VulnTypeLinux      = "linux"
	VulnTypeMacOS      = "macos"
	VulnTypeUnix       = "unix"
	VulnTypeContainer  = "container"
	VulnTypeKubernetes = "kubernetes"
	VulnTypeDatabase   = "database"
	VulnTypeDAST       = "dast"

	// Cloud Security (CSPM)
	VulnTypeAWSCloud        = "aws-cloud"
	VulnTypeAzureCloud      = "azure-cloud"
	VulnTypeGCPCloud        = "gcp-cloud"
	VulnTypeOCICloud        = "oci-cloud"
	VulnTypeAlibabaCloud    = "alibaba-cloud"
	VulnTypeKubernetesCloud = "kubernetes-cloud"
	VulnTypeCloud           = "cloud"

	// Code Security (ASPM)
	VulnTypeSAST   = "sast"
	VulnTypeSCA    = "sca"
	VulnTypeSecret = "secret"
	VulnTypeIaC    = "iac"
	VulnTypeCode   = "code"

	// Attack Surface & Additional Domains
	VulnTypeASM           = "asm"
	VulnTypeCertificate   = "certificate"
	VulnTypeIdentity      = "identity"
	VulnTypeConfiguration = "configuration"
	VulnTypeCompliance    = "compliance"
	VulnTypeEndpoint      = "endpoint"
	VulnTypeFirmware      = "firmware"

	// Legacy Fallbacks
	VulnTypeAgentScan   = "agent-scan"
	VulnTypeCodeSAST    = "code-sast"
	VulnTypeCodeSCA     = "code-sca"
	VulnTypeApplication = "application"
)

// GetHostOSVulnType returns the default OS-specific vuln_type ("windows", "macos", or "linux")
func GetHostOSVulnType() string {
	switch runtime.GOOS {
	case "windows":
		return VulnTypeWindows
	case "darwin":
		return VulnTypeMacOS
	default:
		return VulnTypeLinux
	}
}

// Finding represents a single security issue (hardening, configuration, privesc, or vulnerability)
// detected on the host. Its fields map directly to the backend Vulnerability model and AgentVulnParserService.
type Finding struct {
	// UniversalVulnID is a deterministic unique identifier for deduplication across scans
	UniversalVulnID string `json:"universal_vuln_id"`
	// Title is the concise human-readable name of the finding
	Title string `json:"title"`
	// Description provides detailed context on the issue and why it poses a risk
	Description string `json:"description"`
	// Severity can be: critical, high, medium, low, info
	Severity string `json:"severity"`
	// VulnType specifies the fine-grained vulnerability taxonomy type (e.g., linux, windows, configuration, secret)
	VulnType string `json:"vuln_type"`
	// Category is one of: hardening, configuration, privilege_escalation, vulnerability
	Category string `json:"category"`
	// Type maps to the vulnerability classification category (e.g., hardening, configuration, etc.)
	Type string `json:"type"`
	// SourceClassifier tells the backend the source category (e.g. "config", "code-sca", etc.)
	SourceClassifier string `json:"source_classifier"`
	// MatchedAt indicates the specific file, sysctl key, binary, or configuration line
	MatchedAt string `json:"matched_at"`
	// MatcherName identifies the specific check rule that triggered
	MatcherName string `json:"matcher_name"`
	// Remediation contains actionable instructions to resolve the finding
	Remediation string `json:"remediation"`
	// References lists helpful documentation, CVE advisories, or security benchmarks (e.g., CIS)
	References []string `json:"references,omitempty"`
	// Tags categorizes the finding for easy filtering
	Tags []string `json:"tags,omitempty"`
	// CVE optionally associates a CVE identifier if applicable
	CVE string `json:"cve,omitempty"`
	// DetectedAt is when this issue was found on the host
	DetectedAt time.Time `json:"detected_at"`
	// Raw contains additional diagnostic data for backend storage and triage
	Raw map[string]interface{} `json:"_raw,omitempty"`
}

// Detector defines the interface each host security detector must satisfy.
type Detector interface {
	// Name returns the unique name of the detector module
	Name() string
	// Category returns the detector category
	Category() string
	// Run executes the detector's checks on the host and returns any findings
	Run(ctx context.Context) ([]Finding, error)
}
