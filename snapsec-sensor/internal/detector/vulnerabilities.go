package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// VulnerabilitiesDetector detects known kernel CVEs, vulnerable system components, and pending security updates.
type VulnerabilitiesDetector struct{}

func NewVulnerabilitiesDetector() *VulnerabilitiesDetector {
	return &VulnerabilitiesDetector{}
}

func (d *VulnerabilitiesDetector) Name() string {
	return "vulnerabilities"
}

func (d *VulnerabilitiesDetector) Category() string {
	return "vulnerability"
}

func (d *VulnerabilitiesDetector) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	if runtime.GOOS == "linux" {
		findings = append(findings, d.checkKernelVulnerabilities()...)
		findings = append(findings, d.checkCriticalBinaries()...)
		findings = append(findings, d.checkPendingSecurityUpdates()...)
	}

	for i := range findings {
		if findings[i].VulnType == "" {
			findings[i].VulnType = GetHostOSVulnType()
		}
	}

	return findings, nil
}

// Semver comparison helper (major.minor.patch)
type kernelVersion struct {
	major int
	minor int
	patch int
	extra string
}

func parseKernelVersion(vStr string) kernelVersion {
	// e.g. "5.15.0-88-generic" or "6.2.0-37-generic"
	vStr = strings.TrimSpace(vStr)
	re := regexp.MustCompile(`^(\d+)\.(\d+)(?:\.(\d+))?(?:-(.*))?`)
	matches := re.FindStringSubmatch(vStr)
	if len(matches) < 3 {
		return kernelVersion{}
	}

	major, _ := strconv.Atoi(matches[1])
	minor, _ := strconv.Atoi(matches[2])
	patch := 0
	extra := ""
	if len(matches) > 3 && matches[3] != "" {
		patch, _ = strconv.Atoi(matches[3])
	}
	if len(matches) > 4 {
		extra = matches[4]
	}

	return kernelVersion{major: major, minor: minor, patch: patch, extra: extra}
}

// checkKernelVulnerabilities evaluates the running Linux kernel version against prominent local privilege escalations
func (d *VulnerabilitiesDetector) checkKernelVulnerabilities() []Finding {
	var findings []Finding

	out, err := exec.Command("uname", "-r").Output()
	if err != nil {
		return findings
	}
	rawVersion := strings.TrimSpace(string(out))
	kv := parseKernelVersion(rawVersion)
	if kv.major == 0 {
		return findings
	}

	// 1. Dirty Pipe (CVE-2022-0847)
	// Affects Linux kernel 5.8 through 5.16.10, 5.15.24, 5.10.101
	isDirtyPipe := false
	if (kv.major == 5 && kv.minor >= 8 && kv.minor <= 15) || (kv.major == 5 && kv.minor == 16 && kv.patch < 11) {
		// If on unpatched 5.10 (< 5.10.102) or 5.15 (< 5.15.25)
		if kv.minor == 10 && kv.patch < 102 {
			isDirtyPipe = true
		} else if kv.minor == 15 && kv.patch < 25 {
			isDirtyPipe = true
		} else if kv.minor > 10 && kv.minor < 15 {
			isDirtyPipe = true
		} else if kv.minor == 16 && kv.patch < 11 {
			isDirtyPipe = true
		}
	}

	if isDirtyPipe {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:vuln:kernel-dirty-pipe-cve-2022-0847",
			Title:            fmt.Sprintf("Linux Kernel Vulnerable to Dirty Pipe (CVE-2022-0847) [%s]", rawVersion),
			Description:      fmt.Sprintf("The running kernel version %s is within the vulnerable range for CVE-2022-0847 (Dirty Pipe). A flaw in the Linux kernel pipe buffer handling allows unprivileged local users to overwrite data in arbitrary read-only files (including /etc/passwd or SUID binaries), resulting in complete local root privilege escalation.", rawVersion),
			Severity:         "critical",
			Category:         "vulnerability",
			Type:             "vulnerability",
			SourceClassifier: "config",
			MatchedAt:        fmt.Sprintf("Kernel: %s", rawVersion),
			MatcherName:      "kernel_dirty_pipe",
			Remediation:      "Upgrade the Linux kernel to version 5.16.11, 5.15.25, 5.10.102 or later, and reboot the system.",
			References:       []string{"https://dirtypipe.cm4all.com/", "https://nvd.nist.gov/vuln/detail/CVE-2022-0847"},
			Tags:             []string{"cve", "kernel", "dirtypipe", "privilege-escalation"},
			CVE:              "CVE-2022-0847",
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"kernel_release": rawVersion, "cve": "CVE-2022-0847"},
		})
	}

	// 2. Dirty COW (CVE-2016-5195)
	// Affects Linux kernel < 4.8.3
	if kv.major < 4 || (kv.major == 4 && kv.minor < 8) || (kv.major == 4 && kv.minor == 8 && kv.patch < 3) {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:vuln:kernel-dirty-cow-cve-2016-5195",
			Title:            fmt.Sprintf("Linux Kernel Vulnerable to Dirty COW (CVE-2016-5195) [%s]", rawVersion),
			Description:      fmt.Sprintf("The running kernel %s is vulnerable to CVE-2016-5195 (Dirty COW). A race condition in the kernel memory subsystem's copy-on-write (COW) breakage allows local users to modify read-only memory mappings to gain root privileges.", rawVersion),
			Severity:         "critical",
			Category:         "vulnerability",
			Type:             "vulnerability",
			SourceClassifier: "config",
			MatchedAt:        fmt.Sprintf("Kernel: %s", rawVersion),
			MatcherName:      "kernel_dirty_cow",
			Remediation:      "Upgrade to a modern supported kernel distribution.",
			References:       []string{"https://dirtycow.ninja/", "https://nvd.nist.gov/vuln/detail/CVE-2016-5195"},
			Tags:             []string{"cve", "kernel", "dirtycow", "privilege-escalation"},
			CVE:              "CVE-2016-5195",
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"kernel_release": rawVersion, "cve": "CVE-2016-5195"},
		})
	}

	return findings
}

// checkCriticalBinaries tests for high-impact CVEs in ubiquitous system binaries (Sudo, Polkit, OpenSSL)
func (d *VulnerabilitiesDetector) checkCriticalBinaries() []Finding {
	var findings []Finding

	// 1. Sudo Baron Samedit (CVE-2021-3156)
	// Versions 1.8.2 to 1.8.31p2, and 1.9.0 to 1.9.5p1
	if _, err := exec.LookPath("sudo"); err == nil {
		out, err := exec.Command("sudo", "--version").Output()
		if err == nil {
			firstLine := strings.Split(string(out), "\n")[0]
			re := regexp.MustCompile(`Sudo version\s+([0-9]+\.[0-9]+\.[0-9]+(?:p[0-9]+)?)`)
			m := re.FindStringSubmatch(firstLine)
			if len(m) > 1 {
				verStr := m[1]
				isBaronSamedit := false
				if strings.HasPrefix(verStr, "1.8.") {
					isBaronSamedit = true
				} else if strings.HasPrefix(verStr, "1.9.") {
					parts := strings.Split(verStr, ".")
					if len(parts) >= 3 {
						patchPart := parts[2]
						patchNum, _ := strconv.Atoi(strings.Split(patchPart, "p")[0])
						if patchNum < 5 {
							isBaronSamedit = true
						} else if patchNum == 5 && strings.HasPrefix(patchPart, "5p1") {
							isBaronSamedit = true
						}
					}
				}

				if isBaronSamedit {
					findings = append(findings, Finding{
						UniversalVulnID:  "snapsec:vuln:sudo-baron-samedit-cve-2021-3156",
						Title:            fmt.Sprintf("Sudo Vulnerable to Baron Samedit Heap Overflow (CVE-2021-3156) [%s]", verStr),
						Description:      fmt.Sprintf("Installed sudo version %s is susceptible to CVE-2021-3156 (Baron Samedit). A heap-based buffer overflow in command-line argument unescaping allows any local user without sudo privileges to execute commands as root.", verStr),
						Severity:         "critical",
						Category:         "vulnerability",
						Type:             "vulnerability",
						SourceClassifier: "config",
						MatchedAt:        firstLine,
						MatcherName:      "sudo_baron_samedit",
						Remediation:      "Upgrade the sudo package ('sudo apt update && sudo apt install --only-upgrade sudo' or 'yum update sudo') to version 1.9.5p2 or later.",
						References:       []string{"https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt", "https://nvd.nist.gov/vuln/detail/CVE-2021-3156"},
						Tags:             []string{"cve", "sudo", "privilege-escalation"},
						CVE:              "CVE-2021-3156",
						DetectedAt:       time.Now(),
						Raw:              map[string]interface{}{"sudo_version": verStr, "cve": "CVE-2021-3156"},
					})
				}
			}
		}
	}

	// 2. OpenSSL 3.0.0 - 3.0.6 Buffer Overflow (CVE-2022-3602, CVE-2022-3786)
	if _, err := exec.LookPath("openssl"); err == nil {
		out, err := exec.Command("openssl", "version").Output()
		if err == nil {
			vLine := strings.TrimSpace(string(out))
			re := regexp.MustCompile(`OpenSSL\s+3\.0\.([0-6])`)
			if re.MatchString(vLine) {
				findings = append(findings, Finding{
					UniversalVulnID:  "snapsec:vuln:openssl-cve-2022-3602",
					Title:            fmt.Sprintf("OpenSSL Vulnerable to X.509 Email Address Buffer Overflows (CVE-2022-3602) [%s]", vLine),
					Description:      fmt.Sprintf("The installed %s suffers from buffer overflow vulnerabilities (CVE-2022-3602 and CVE-2022-3786) in X.509 certificate verification, which could trigger denial of service or remote code execution.", vLine),
					Severity:         "high",
					Category:         "vulnerability",
					Type:             "vulnerability",
					SourceClassifier: "config",
					MatchedAt:        vLine,
					MatcherName:      "openssl_version_audit",
					Remediation:      "Upgrade OpenSSL to version 3.0.7 or later via system package manager.",
					References:       []string{"https://www.openssl.org/news/secadv/20221101.txt", "https://nvd.nist.gov/vuln/detail/CVE-2022-3602"},
					Tags:             []string{"cve", "openssl", "memory-corruption"},
					CVE:              "CVE-2022-3602",
					DetectedAt:       time.Now(),
					Raw:              map[string]interface{}{"openssl_version": vLine, "cve": "CVE-2022-3602"},
				})
			}
		}
	}

	return findings
}

// checkPendingSecurityUpdates checks system package managers for unapplied security advisories
func (d *VulnerabilitiesDetector) checkPendingSecurityUpdates() []Finding {
	var findings []Finding

	// 1. Ubuntu/Debian /var/lib/update-notifier/updates-available
	infoPath := "/var/lib/update-notifier/updates-available"
	if f, err := os.Open(infoPath); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		reSecurity := regexp.MustCompile(`(\d+)\s+updates\s+are\s+security\s+updates`)
		for scanner.Scan() {
			line := scanner.Text()
			m := reSecurity.FindStringSubmatch(line)
			if len(m) > 1 {
				count, _ := strconv.Atoi(m[1])
				if count > 0 {
					findings = append(findings, Finding{
						UniversalVulnID:  "snapsec:vuln:pending-security-updates-debian",
						Title:            fmt.Sprintf("%d Unapplied System Security Updates Pending Installation", count),
						Description:      fmt.Sprintf("The system package manager reports %d security updates waiting to be installed. Leaving security updates unapplied leaves the host vulnerable to publicly known exploits.", count),
						Severity:         "high",
						Category:         "vulnerability",
						Type:             "vulnerability",
						SourceClassifier: "config",
						MatchedAt:        fmt.Sprintf("%s: %s", infoPath, line),
						MatcherName:      "pending_security_updates",
						Remediation:      "Install pending security updates by running 'sudo apt update && sudo apt upgrade -y'.",
						References:       []string{"https://ubuntu.com/security/notices"},
						Tags:             []string{"patching", "security-updates", "cve"},
						DetectedAt:       time.Now(),
						Raw:              map[string]interface{}{"pending_security_count": count},
					})
				}
			}
		}
	}

	return findings
}
