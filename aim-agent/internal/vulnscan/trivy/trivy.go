package trivy

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
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

type TrivyScanner struct {
	config  vulnscan.PluginConfig
	binPath string
}

func (t *TrivyScanner) Init(config vulnscan.PluginConfig) error {
	t.config = config

	if err := os.MkdirAll(t.config.BinDir, 0755); err != nil {
		return fmt.Errorf("failed to create bin dir: %w", err)
	}

	binName := "trivy"
	if runtime.GOOS == "windows" {
		binName = "trivy.exe"
	}
	t.binPath = filepath.Join(t.config.BinDir, binName)

	if _, err := os.Stat(t.binPath); os.IsNotExist(err) {
		log.Println("Trivy binary not found. Downloading...")
		if err := t.downloadTrivy(); err != nil {
			return fmt.Errorf("failed to download trivy: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("error checking trivy binary: %w", err)
	}

	return nil
}

func (t *TrivyScanner) downloadTrivy() error {
	version := "0.72.0"
	osName := runtime.GOOS
	if osName == "darwin" {
		osName = "macOS"
	} else if osName == "windows" {
		osName = "Windows"
	} else if osName == "linux" {
		osName = "Linux"
	}

	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "64bit"
	} else if arch == "arm64" {
		arch = "ARM64"
	}

	isZip := runtime.GOOS == "windows"
	ext := "tar.gz"
	if isZip {
		ext = "zip"
	}

	fileName := fmt.Sprintf("trivy_%s_%s-%s.%s", version, osName, arch, ext)
	downloadURL := fmt.Sprintf("https://github.com/aquasecurity/trivy/releases/download/v%s/%s", version, fileName)
	log.Printf("Downloading Trivy from %s", downloadURL)

	resp, err := http.Get(downloadURL)
	if err != nil {
		return fmt.Errorf("failed to download trivy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to download trivy: HTTP %d", resp.StatusCode)
	}

	tmpFile, err := os.CreateTemp("", "trivy-*."+ext)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := io.Copy(tmpFile, resp.Body); err != nil {
		return fmt.Errorf("failed to write downloaded file: %w", err)
	}
	tmpFile.Close()

	expectedBinName := "trivy"
	if runtime.GOOS == "windows" {
		expectedBinName = "trivy.exe"
	}

	if isZip {
		err = extractZip(tmpFile.Name(), expectedBinName, t.binPath)
	} else {
		err = extractTarGz(tmpFile.Name(), expectedBinName, t.binPath)
	}

	if err != nil {
		return err
	}

	log.Printf("Successfully downloaded and extracted Trivy to %s", t.binPath)
	return nil
}

func extractZip(zipPath, expectedBinName, destPath string) error {
	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer zipReader.Close()

	var binFile *zip.File
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

	return writeBinary(rc, destPath)
}

func extractTarGz(tarPath, expectedBinName, destPath string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("failed to open tar file: %w", err)
	}
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("failed to read tar header: %w", err)
		}

		if header.Name == expectedBinName {
			return writeBinary(tr, destPath)
		}
	}

	return fmt.Errorf("binary %s not found in tarball", expectedBinName)
}

func writeBinary(r io.Reader, destPath string) error {
	outFile, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return fmt.Errorf("failed to create binary file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, r); err != nil {
		return fmt.Errorf("failed to write binary: %w", err)
	}
	return nil
}

func (t *TrivyScanner) Capabilities() []vulnscan.ScanType {
	return []vulnscan.ScanType{"container", "fs", "repository"}
}

func (t *TrivyScanner) Execute(ctx context.Context, job vulnscan.ScanJob) (vulnscan.ScanResult, error) {
	result := vulnscan.ScanResult{JobID: job.ID}

	if len(job.Targets) == 0 {
		return result, fmt.Errorf("no targets specified for trivy scan")
	}

	mode := "fs"
	if m, ok := job.Options["mode"]; ok && m != "" {
		mode = m
	}

	target := job.Targets[0] // Trivy typically takes one target at a time.

	outputFile, err := os.CreateTemp("", "trivy-output-*.json")
	if err != nil {
		return result, fmt.Errorf("failed to create output file: %w", err)
	}
	defer os.Remove(outputFile.Name())
	outputFile.Close()

	args := []string{
		mode,
		"-f", "json",
		"-o", outputFile.Name(),
		"--quiet", // To prevent pollution in stderr
	}

	if ex, ok := job.Options["excludes"]; ok && ex != "" {
		for _, e := range strings.Split(ex, ",") {
			args = append(args, "--skip-dirs", strings.TrimSpace(e))
		}
	}

	args = append(args, target)

	cmd := exec.CommandContext(ctx, t.binPath, args...)

	if err := cmd.Run(); err != nil {
		log.Printf("Trivy execution finished with error (expected if vulns found): %v", err)
	}

	rawOutput, err := os.ReadFile(outputFile.Name())
	if err != nil {
		return result, fmt.Errorf("failed to read trivy output: %w", err)
	}

	findings, err := t.Normalize(rawOutput)
	if err != nil {
		return result, fmt.Errorf("failed to normalize trivy output: %w", err)
	}

	result.Findings = findings
	return result, nil
}

func (t *TrivyScanner) Normalize(rawOutput []byte) ([]vulnscan.NormalizedFinding, error) {
	var findings []vulnscan.NormalizedFinding
	if len(rawOutput) == 0 {
		return findings, nil
	}

	var trivyReport struct {
		Results []struct {
			Target          string `json:"Target"`
			Class           string `json:"Class"`
			Type            string `json:"Type"`
			Vulnerabilities []struct {
				VulnerabilityID  string   `json:"VulnerabilityID"`
				PkgName          string   `json:"PkgName"`
				InstalledVersion string   `json:"InstalledVersion"`
				FixedVersion     string   `json:"FixedVersion"`
				Title            string   `json:"Title"`
				Description      string   `json:"Description"`
				Severity         string   `json:"Severity"`
				References       []string `json:"References"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(rawOutput, &trivyReport); err != nil {
		return nil, fmt.Errorf("failed to parse trivy JSON output: %w", err)
	}

	for _, res := range trivyReport.Results {
		for _, vuln := range res.Vulnerabilities {
			severity := strings.ToLower(vuln.Severity)
			if severity == "" || severity == "unknown" {
				severity = "info"
			}

			remediation := ""
			if vuln.FixedVersion != "" {
				remediation = fmt.Sprintf("Upgrade %s to %s", vuln.PkgName, vuln.FixedVersion)
			}

			finding := vulnscan.NormalizedFinding{
				FindingID:     fmt.Sprintf("trivy-%s-%s", vuln.VulnerabilityID, vuln.PkgName),
				Scanner:       "trivy",
				Category:      res.Class,
				Title:         vuln.Title,
				Severity:      severity,
				Description:   vuln.Description,
				Evidence:      fmt.Sprintf("Found %s (version %s) in %s", vuln.VulnerabilityID, vuln.InstalledVersion, res.Target),
				Remediation:   remediation,
				References:    vuln.References,
				CVEs:          []string{vuln.VulnerabilityID},
				AffectedAsset: res.Target,
				Metadata: map[string]interface{}{
					"pkg_name":          vuln.PkgName,
					"installed_version": vuln.InstalledVersion,
					"fixed_version":     vuln.FixedVersion,
					"type":              res.Type,
				},
			}
			
			if finding.Title == "" {
				finding.Title = vuln.VulnerabilityID
			}

			findings = append(findings, finding)
		}
	}

	return findings, nil
}

func (t *TrivyScanner) Cleanup() error {
	return nil
}
