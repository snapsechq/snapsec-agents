package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// PrivEscDetector audits host configurations for vectors commonly exploited for local privilege escalation (LPE).
type PrivEscDetector struct{}

func NewPrivEscDetector() *PrivEscDetector {
	return &PrivEscDetector{}
}

func (d *PrivEscDetector) Name() string {
	return "privilege_escalation"
}

func (d *PrivEscDetector) Category() string {
	return "privilege_escalation"
}

func (d *PrivEscDetector) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	if runtime.GOOS == "linux" {
		findings = append(findings, d.checkSudoersEscalations()...)
		findings = append(findings, d.checkSUIDBinaries()...)
		findings = append(findings, d.checkWritableCronAndSystemd()...)
		findings = append(findings, d.checkRootPathSecurity()...)
		findings = append(findings, d.checkNFSNoRootSquash()...)
	}

	for i := range findings {
		if findings[i].VulnType == "" {
			findings[i].VulnType = GetHostOSVulnType()
		}
	}

	return findings, nil
}

// Known GTFOBins binaries that trivially allow shell breakouts or file overrides when granted SUID or sudo NOPASSWD
var gtfobins = map[string]string{
	"bash":       "Shell escape / interactive root prompt",
	"sh":         "Shell escape / interactive root prompt",
	"zsh":        "Shell escape / interactive root prompt",
	"python":     "Python interpreter enables execution of arbitrary system commands",
	"python3":    "Python interpreter enables execution of arbitrary system commands",
	"perl":       "Perl exec enables arbitrary command execution",
	"ruby":       "Ruby exec enables arbitrary command execution",
	"lua":        "Lua os.execute enables arbitrary command execution",
	"vim":        "Vim :!/bin/sh command execution",
	"vi":         "Vi shell escape",
	"nano":       "Nano spell check or child process spawn",
	"find":       "find -exec /bin/sh enables arbitrary root command execution",
	"awk":        "awk system() function executes arbitrary commands as root",
	"gawk":       "gawk system() function executes arbitrary commands as root",
	"sed":        "sed execute / write capabilities",
	"less":       "less !/bin/sh interactive escape",
	"more":       "more !/bin/sh interactive escape",
	"man":        "man pager shell escape",
	"tar":        "tar --checkpoint-action enables arbitrary command execution",
	"zip":        "zip -T --unzip-command execution",
	"cp":         "Arbitrary file overwrite (e.g. overwriting /etc/passwd or /etc/shadow)",
	"mv":         "Arbitrary file move / replacement",
	"curl":       "Arbitrary file write to sensitive paths or SSRF",
	"wget":       "Arbitrary file overwrite / download to system directories",
	"nmap":       "nmap --interactive or NSE script execution",
	"env":        "env /bin/sh spawns shell with target permissions",
	"socat":      "socat reverse/bind shell execution",
	"nc":         "netcat arbitrary command execution or root reverse shell",
	"netcat":     "netcat arbitrary command execution or root reverse shell",
	"tee":        "tee arbitrary file append to /etc/sudoers or /etc/passwd",
	"chmod":      "chmod can modify permissions of /etc/shadow or executables",
	"chown":      "chown can transfer ownership of sensitive binaries or files",
	"journalctl": "journalctl !/bin/sh pager breakout",
	"systemctl":  "systemctl service unit creation or status pager breakout",
}

// checkSudoersEscalations analyzes sudoers configuration for dangerous NOPASSWD directives and env_keep overrides
func (d *PrivEscDetector) checkSudoersEscalations() []Finding {
	var findings []Finding

	files := []string{"/etc/sudoers"}
	dropins, _ := filepath.Glob("/etc/sudoers.d/*")
	files = append(files, dropins...)

	for _, file := range files {
		f, err := os.Open(file)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}

			// 1. Check for LD_PRELOAD in env_keep
			if strings.Contains(line, "env_keep") && (strings.Contains(line, "LD_PRELOAD") || strings.Contains(line, "LD_LIBRARY_PATH")) {
				findings = append(findings, Finding{
					UniversalVulnID:  fmt.Sprintf("snapsec:privesc:sudo-ld-preload-%s", filepath.Base(file)),
					Title:            "Sudoers Configuration Preserves LD_PRELOAD (Instant Root Escalation)",
					Description:      fmt.Sprintf("%s configures env_keep with LD_PRELOAD or LD_LIBRARY_PATH. Any authorized sudo user can inject a custom shared library to execute arbitrary code with root privileges.", file),
					Severity:         "critical",
					Category:         "privilege_escalation",
					Type:             "privilege_escalation",
					SourceClassifier: "config",
					MatchedAt:        fmt.Sprintf("%s: %s", file, line),
					MatcherName:      "sudoers_env_keep_preload",
					Remediation:      "Remove LD_PRELOAD and LD_LIBRARY_PATH from env_keep directives in sudoers.",
					References:       []string{"https://gtfobins.github.io/#+sudo"},
					Tags:             []string{"sudo", "privilege-escalation", "gtfobins"},
					DetectedAt:       time.Now(),
				})
			}

			// 2. Check for NOPASSWD on GTFOBins binaries
			if strings.Contains(line, "NOPASSWD") {
				upperLine := strings.ToUpper(line)
				// Check for NOPASSWD: ALL
				if strings.Contains(upperLine, "NOPASSWD: ALL") || strings.Contains(upperLine, "NOPASSWD:ALL") {
					findings = append(findings, Finding{
						UniversalVulnID:  fmt.Sprintf("snapsec:privesc:sudo-nopasswd-all-%s", filepath.Base(file)),
						Title:            "Sudoers Grants Full NOPASSWD: ALL Privileges",
						Description:      fmt.Sprintf("%s contains '%s', allowing users to execute any command as root without password verification.", file, line),
						Severity:         "high",
						Category:         "privilege_escalation",
						Type:             "privilege_escalation",
						SourceClassifier: "config",
						MatchedAt:        fmt.Sprintf("%s: %s", file, line),
						MatcherName:      "sudoers_nopasswd_all",
						Remediation:      "Enforce password verification for administrative commands by removing the NOPASSWD flag.",
						References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
						Tags:             []string{"sudo", "authentication", "privilege-escalation"},
						DetectedAt:       time.Now(),
					})
				} else {
					// Check for specific GTFOBins
					for bin, risk := range gtfobins {
						if strings.Contains(line, "/"+bin) || strings.Contains(line, " "+bin) {
							findings = append(findings, Finding{
								UniversalVulnID:  fmt.Sprintf("snapsec:privesc:sudo-nopasswd-gtfobin-%s-%s", filepath.Base(file), bin),
								Title:            fmt.Sprintf("Sudoers Allows NOPASSWD Execution of GTFOBin '%s'", bin),
								Description:      fmt.Sprintf("%s allows passwordless sudo execution of '%s'. %s.", file, bin, risk),
								Severity:         "critical",
								Category:         "privilege_escalation",
								Type:             "privilege_escalation",
								SourceClassifier: "config",
								MatchedAt:        fmt.Sprintf("%s: %s", file, line),
								MatcherName:      "sudoers_dangerous_binary",
								Remediation:      fmt.Sprintf("Remove NOPASSWD authorization for '%s' or restrict arguments using a custom wrapper script.", bin),
								References:       []string{"https://gtfobins.github.io/" + bin + "/#sudo"},
								Tags:             []string{"sudo", "gtfobins", "privilege-escalation"},
								DetectedAt:       time.Now(),
							})
						}
					}
				}
			}
		}
		f.Close()
	}

	return findings
}

// checkSUIDBinaries scans filesystem search paths for dangerous or misplaced SUID/SGID binaries
func (d *PrivEscDetector) checkSUIDBinaries() []Finding {
	var findings []Finding

	searchDirs := []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
		"/tmp", "/var/tmp", "/dev/shm",
	}

	for _, dir := range searchDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			fullPath := filepath.Join(dir, entry.Name())
			info, err := os.Lstat(fullPath)
			if err != nil {
				continue
			}

			mode := info.Mode()
			// Check if SUID bit is set
			if mode&os.ModeSetuid != 0 {
				stat, ok := info.Sys().(*syscall.Stat_t)
				if !ok {
					continue
				}

				// 1. SUID binaries in temporary or world-writable directories
				if dir == "/tmp" || dir == "/var/tmp" || dir == "/dev/shm" {
					findings = append(findings, Finding{
						UniversalVulnID:  fmt.Sprintf("snapsec:privesc:suid-temp-dir-%s", entry.Name()),
						Title:            fmt.Sprintf("SUID Binary Located in Temporary Directory (%s)", fullPath),
						Description:      fmt.Sprintf("A SUID binary was found at %s. SUID binaries in world-writable paths are strong indicators of attacker persistence or root privilege escalation artifacts.", fullPath),
						Severity:         "critical",
						Category:         "privilege_escalation",
						Type:             "privilege_escalation",
						SourceClassifier: "config",
						MatchedAt:        fullPath,
						MatcherName:      "suid_temp_directory",
						Remediation:      fmt.Sprintf("Investigate the binary origin and remove it: 'rm -f %s'. Ensure /tmp and /dev/shm are mounted with 'nosuid'.", fullPath),
						References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
						Tags:             []string{"suid", "persistence", "privilege-escalation"},
						DetectedAt:       time.Now(),
					})
				}

				// 2. Dangerous GTFOBins binaries owned by root with SUID set
				if stat.Uid == 0 {
					baseName := entry.Name()
					if desc, exists := gtfobins[baseName]; exists {
						findings = append(findings, Finding{
							UniversalVulnID:  fmt.Sprintf("snapsec:privesc:suid-gtfobin-%s", baseName),
							Title:            fmt.Sprintf("Dangerous GTFOBin With Root SUID Bit Set (%s)", fullPath),
							Description:      fmt.Sprintf("The binary %s has the SUID bit set and is owned by root. %s.", fullPath, desc),
							Severity:         "critical",
							Category:         "privilege_escalation",
							Type:             "privilege_escalation",
							SourceClassifier: "config",
							MatchedAt:        fullPath,
							MatcherName:      "suid_gtfobin",
							Remediation:      fmt.Sprintf("Strip the SUID permission: 'chmod u-s %s'.", fullPath),
							References:       []string{"https://gtfobins.github.io/" + baseName + "/#suid"},
							Tags:             []string{"suid", "gtfobins", "privilege-escalation"},
							DetectedAt:       time.Now(),
						})
					}
				}
			}
		}
	}

	return findings
}

// checkWritableCronAndSystemd checks for cron scripts and systemd unit files writable by unprivileged users
func (d *PrivEscDetector) checkWritableCronAndSystemd() []Finding {
	var findings []Finding

	// 1. Audit /etc/crontab and /etc/cron.*
	cronDirs := []string{"/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly"}
	for _, cd := range cronDirs {
		entries, err := os.ReadDir(cd)
		if err != nil {
			continue
		}
		for _, e := range entries {
			fp := filepath.Join(cd, e.Name())
			info, err := os.Stat(fp)
			if err != nil {
				continue
			}
			// Check if world-writable
			if info.Mode().Perm()&0002 != 0 {
				findings = append(findings, Finding{
					UniversalVulnID:  fmt.Sprintf("snapsec:privesc:writable-cron-%s", e.Name()),
					Title:            fmt.Sprintf("Cron Script (%s) Is World-Writable", fp),
					Description:      fmt.Sprintf("Cron job script %s is world-writable (mode %04o). Any local user can append commands that will execute with root privileges when cron runs.", fp, info.Mode().Perm()),
					Severity:         "critical",
					Category:         "privilege_escalation",
					Type:             "privilege_escalation",
					SourceClassifier: "config",
					MatchedAt:        fmt.Sprintf("%s (mode: %04o)", fp, info.Mode().Perm()),
					MatcherName:      "cron_world_writable",
					Remediation:      fmt.Sprintf("Run 'chmod 0755 %s' and ensure it is owned by root:root.", fp),
					References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
					Tags:             []string{"cron", "permissions", "privilege-escalation"},
					DetectedAt:       time.Now(),
				})
			}
		}
	}

	// 2. Audit /etc/systemd/system/*.service units
	systemdUnits, _ := filepath.Glob("/etc/systemd/system/*.service")
	for _, unit := range systemdUnits {
		info, err := os.Stat(unit)
		if err != nil {
			continue
		}
		if info.Mode().Perm()&0002 != 0 {
			findings = append(findings, Finding{
				UniversalVulnID:  fmt.Sprintf("snapsec:privesc:writable-systemd-%s", filepath.Base(unit)),
				Title:            fmt.Sprintf("Systemd Service Unit (%s) Is World-Writable", filepath.Base(unit)),
				Description:      fmt.Sprintf("Unit file %s is world-writable. Unprivileged users can edit ExecStart to execute commands as root when the service starts or restarts.", unit),
				Severity:         "critical",
				Category:         "privilege_escalation",
				Type:             "privilege_escalation",
				SourceClassifier: "config",
				MatchedAt:        fmt.Sprintf("%s (mode: %04o)", unit, info.Mode().Perm()),
				MatcherName:      "systemd_world_writable",
				Remediation:      fmt.Sprintf("Run 'chmod 0644 %s' and set ownership to root:root.", unit),
				References:       []string{"https://www.freedesktop.org/software/systemd/man/systemd.service.html"},
				Tags:             []string{"systemd", "permissions", "privilege-escalation"},
				DetectedAt:       time.Now(),
			})
		}
	}

	return findings
}

// checkRootPathSecurity checks if root's PATH environment contains relative directories or world-writable paths
func (d *PrivEscDetector) checkRootPathSecurity() []Finding {
	var findings []Finding

	pathEnv := os.Getenv("PATH")
	entries := strings.Split(pathEnv, ":")

	for _, dir := range entries {
		dir = strings.TrimSpace(dir)
		if dir == "" || dir == "." {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:privesc:root-path-contains-dot",
				Title:            "System PATH Contains Current Working Directory (.)",
				Description:      "The PATH environment variable contains '.' or an empty entry, which causes binaries to be searched in the current working directory first. If root runs commands in /tmp or user directories, trojaned executables can be executed.",
				Severity:         "high",
				Category:         "privilege_escalation",
				Type:             "privilege_escalation",
				SourceClassifier: "config",
				MatchedAt:        "PATH=" + pathEnv,
				MatcherName:      "path_relative_directory",
				Remediation:      "Remove '.' and empty entries from the PATH environment variable in /etc/environment and profile scripts.",
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"path", "privilege-escalation"},
				DetectedAt:       time.Now(),
			})
			break
		}

		// Check if directory is world-writable
		info, err := os.Stat(dir)
		if err == nil && info.Mode().Perm()&0002 != 0 {
			findings = append(findings, Finding{
				UniversalVulnID:  fmt.Sprintf("snapsec:privesc:root-path-writable-%s", filepath.Base(dir)),
				Title:            fmt.Sprintf("PATH Entry (%s) Is World-Writable", dir),
				Description:      fmt.Sprintf("Directory %s in system PATH is world-writable. Any user can plant an executable that root will unwittingly execute.", dir),
				Severity:         "critical",
				Category:         "privilege_escalation",
				Type:             "privilege_escalation",
				SourceClassifier: "config",
				MatchedAt:        fmt.Sprintf("%s (mode: %04o)", dir, info.Mode().Perm()),
				MatcherName:      "path_directory_writable",
				Remediation:      fmt.Sprintf("Run 'chmod 0755 %s' and ensure root ownership.", dir),
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"path", "permissions", "privilege-escalation"},
				DetectedAt:       time.Now(),
			})
		}
	}

	return findings
}

// checkNFSNoRootSquash checks /etc/exports for unsafe no_root_squash flags
func (d *PrivEscDetector) checkNFSNoRootSquash() []Finding {
	var findings []Finding

	exportsFile := "/etc/exports"
	f, err := os.Open(exportsFile)
	if err != nil {
		return findings
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.Contains(line, "no_root_squash") {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:privesc:nfs-no-root-squash",
				Title:            "NFS Export Configured With 'no_root_squash'",
				Description:      fmt.Sprintf("NFS export '%s' has 'no_root_squash' enabled. Remote clients mounting this share as root will maintain UID 0 on the file server, allowing creation of SUID root binaries.", line),
				Severity:         "high",
				Category:         "privilege_escalation",
				Type:             "privilege_escalation",
				SourceClassifier: "config",
				MatchedAt:        fmt.Sprintf("%s: %s", exportsFile, line),
				MatcherName:      "nfs_no_root_squash",
				Remediation:      "Replace 'no_root_squash' with 'root_squash' in /etc/exports and run 'exportfs -ra'.",
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"nfs", "network-shares", "privilege-escalation"},
				DetectedAt:       time.Now(),
			})
		}
	}

	return findings
}
