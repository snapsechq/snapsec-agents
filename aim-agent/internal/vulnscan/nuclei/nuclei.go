package nuclei

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"snapsec-agent/internal/vulnscan"
)

type NucleiScanner struct {
	config vulnscan.PluginConfig
	binPath string
}

func (n *NucleiScanner) Init(config vulnscan.PluginConfig) error {
	n.config = config
	
	// Create bin and template directories
	if err := os.MkdirAll(n.config.BinDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin dir: %w", err)
	}
	if err := os.MkdirAll(n.config.TemplateDir, 0755); err != nil {
		return fmt.Errorf("failed to create template dir: %w", err)
	}

	binName := "nuclei"
	if runtime.GOOS == "windows" {
		binName = "nuclei.exe"
	}
	n.binPath = filepath.Join(n.config.BinDir, binName)

	if _, err := os.Stat(n.binPath); os.IsNotExist(err) {
		log.Println("Nuclei binary not found. Downloading...")
		if err := n.downloadNuclei(); err != nil {
			return fmt.Errorf("failed to download nuclei: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error checking nuclei binary: %w", err)
	}

	// Update templates on init (optional, but good practice if not present)
	templatesPath := filepath.Join(n.config.TemplateDir, "nuclei")
	if _, err := os.Stat(templatesPath); os.IsNotExist(err) {
		log.Println("Nuclei templates not found. Updating...")
		cmd := exec.Command(n.binPath, "-ud", templatesPath, "-update-templates")
		if err := cmd.Run(); err != nil {
			log.Printf("Failed to update nuclei templates: %v", err)
		}
	}

	return nil
}

func (n *NucleiScanner) downloadNuclei() error {
	version := "3.3.0"
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macOS"
	}
	arch := runtime.GOARCH

	downloadURL := fmt.Sprintf("https://github.com/projectdiscovery/nuclei/releases/download/v%s/nuclei_%s_%s_%s.zip", version, version, osName, arch)
	log.Printf("Downloading Nuclei from %s", downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download nuclei: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download nuclei: HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "nuclei-*.zip")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write zip file: %w", err)
	}
	tmpFile.Close()

	zipReader, err := zip.OpenReader(tmpFile.Name())
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer zipReader.Close()

	var binFile *zip.File
	expectedBinName := "nuclei"
	if runtime.GOOS == "windows" {
		expectedBinName = "nuclei.exe"
	}

	for _, f := range zipReader.File {
		if f.Name == expectedBinName {
			binFile = f
			break
		}
	}

	if binFile == nil {
		return fmt.Errorf("binary %s not found in zip", expectedBinName)
	}

	rc, err := binFile.Open()
	if err != nil {
		return fmt.Errorf("failed to open binary in zip: %w", err)
	}
	defer rc.Close()

	outFile, err := os.OpenFile(n.binPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create binary file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, rc); err != nil {
		return fmt.Errorf("failed to write binary: %w", err)
	}

	log.Printf("Successfully downloaded and extracted Nuclei to %s", n.binPath)
	return nil
}

func (n *NucleiScanner) Capabilities() []vulnscan.ScanType {
	return []vulnscan.ScanType{"cve", "misconfiguration", "network", "local-file"}
}

func (n *NucleiScanner) Execute(ctx context.Context, job vulnscan.ScanJob) (vulnscan.ScanResult, error) {
	result := vulnscan.ScanResult{JobID: job.ID}
	
	if len(job.Targets) == 0 {
		return result, fmt.Errorf("no targets specified for nuclei scan")
	}

	// Create a temporary file for targets
	targetFile, err := os.CreateTemp("", "nuclei-targets-*.txt")
	if err != nil {
		return result, fmt.Errorf("failed to create targets file: %w", err)
	}
	defer os.Remove(targetFile.Name())

	for _, target := range job.Targets {
		targetFile.WriteString(target + "\n")
	}
	targetFile.Close()

	outputFile, err := os.CreateTemp("", "nuclei-output-*.json")
	if err != nil {
		return result, fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	templatesPath := filepath.Join(n.config.TemplateDir, "nuclei")

	args := []string{
		"-l", targetFile.Name(),
		"-json-export", outputFile.Name(),
		"-ud", templatesPath,
		"-c", "8",
		"-bs", "8",
		"-rl", "100",
	}

	if pt, ok := job.Options["protocol"]; ok && pt != "" {
		args = append(args, "-pt", pt)
	}
	if tags, ok := job.Options["tags"]; ok && tags != "" {
		args = append(args, "-tags", tags)
	}
	if resumePath, ok := job.Options["resume"]; ok && resumePath != "" {
		args = append(args, "-resume", resumePath)
	}

	isVerbose := job.Options["verbose"] == "true"
	if !isVerbose {
		args = append(args, "-silent")
	}

	cmd := exec.CommandContext(ctx, n.binPath, args...)
	
	if isVerbose {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	
	// Run the command
	if err := cmd.Run(); err != nil {
		// nuclei might return non-zero exit code if it finds vulnerabilities, we should check if outputFile has content
		log.Printf("Nuclei execution finished with error (might be expected if vulns found): %v", err)
	}

	// Read the JSON output
	rawOutput, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return result, fmt.Errorf("failed to read nuclei output: %w", err)
	}

	findings, err := n.Normalize(rawOutput)
	if err != nil {
		return result, fmt.Errorf("failed to normalize nuclei output: %w", err)
	}

	result.Findings = findings
	return result, nil
}

func (n *NucleiScanner) Normalize(rawOutput []byte) ([]vulnscan.NormalizedFinding, error) {
	var findings []vulnscan.NormalizedFinding
	if len(rawOutput) == 0 {
		return findings, nil
	}

	// Nuclei -json-export outputs an array of JSON objects if we use modern Nuclei, 
	// or JSONL depending on the flag. -json-export usually creates an array.
	var rawFindings []map[string]interface{}
	if err := json.Unmarshal(rawOutput, &rawFindings); err != nil {
		// If it's JSONL, we need to split by newline
		lines := strings.Split(string(rawOutput), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var singleFinding map[string]interface{}
			if err := json.Unmarshal([]byte(line), &singleFinding); err != nil {
				return nil, fmt.Errorf("failed to parse nuclei JSON line: %w", err)
			}
			rawFindings = append(rawFindings, singleFinding)
		}
	}

	for _, raw := range rawFindings {
		info, _ := raw["info"].(map[string]interface{})
		severity, _ := info["severity"].(string)
		if severity == "" {
			severity = "info"
		}
		
		name, _ := info["name"].(string)
		desc, _ := info["description"].(string)
		remediation, _ := info["remediation"].(string)
		matchedAt, _ := raw["matched-at"].(string)
		templateID, _ := raw["template-id"].(string)
		
		finding := vulnscan.NormalizedFinding{
			FindingID:     fmt.Sprintf("nuclei-%v-%v", templateID, matchedAt),
			Scanner:       "nuclei",
			Category:      "vulnerability",
			Title:         name,
			Severity:      severity,
			Description:   desc,
			Evidence:      fmt.Sprintf("Matched at %s", matchedAt),
			Remediation:   remediation,
			AffectedAsset: matchedAt,
			Metadata: map[string]interface{}{
				"nuclei_template_id": templateID,
				"raw": raw,
			},
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

func (n *NucleiScanner) Cleanup() error {
	return nil
}
