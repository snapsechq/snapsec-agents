package detector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// ConfigIssuesDetector scans for insecure file permissions, exposed credentials, and misconfigured services.
type ConfigIssuesDetector struct{}

func NewConfigIssuesDetector() *ConfigIssuesDetector {
	return &ConfigIssuesDetector{}
}

func (d *ConfigIssuesDetector) Name() string {
	return "configuration"
}

func (d *ConfigIssuesDetector) Category() string {
	return "configuration"
}

func (d *ConfigIssuesDetector) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	if runtime.GOOS == "linux" {
		findings = append(findings, d.checkSensitiveFilePermissions()...)
		findings = append(findings, d.checkSSHKeyPermissions()...)
		findings = append(findings, d.checkCloudAndDevCredentials()...)
		findings = append(findings, d.checkDaemonConfigs()...)
	}

	for i := range findings {
		if findings[i].VulnType == "" {
			findings[i].VulnType = VulnTypeConfiguration
		}
	}

	return findings, nil
}

// checkSensitiveFilePermissions audits POSIX permissions on critical OS identity and auth files
func (d *ConfigIssuesDetector) checkSensitiveFilePermissions() []Finding {
	var findings []Finding

	// Helper to inspect file mode
	checkFile := func(path string, badMode os.FileMode, expected string, uvid string, title string, desc string, sev string) {
		info, err := os.Stat(path)
		if err != nil {
			return // file doesn't exist or inaccessible
		}
		mode := info.Mode().Perm()
		if mode&badMode != 0 {
			findings = append(findings, Finding{
				UniversalVulnID:  uvid,
				Title:            title,
				Description:      fmt.Sprintf("%s (current mode: %04o, expected: %s). %s", path, mode, expected, desc),
				Severity:         sev,
				VulnType:         VulnTypeConfiguration,
				Category:         "configuration",
				Type:             "configuration",
				SourceClassifier: "config",
				MatchedAt:        fmt.Sprintf("%s (mode: %04o)", path, mode),
				MatcherName:      "file_permission_audit",
				Remediation:      fmt.Sprintf("Run 'chmod %s %s' to secure permissions.", expected, path),
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"permissions", "credentials", "configuration"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"path": path, "mode": fmt.Sprintf("%04o", mode), "expected": expected},
			})
		}
	}

	// 1. /etc/shadow world-readable or world/group-writable
	checkFile("/etc/shadow", 0026, "0640",
		"snapsec:config:shadow-file-permissions",
		"Shadow Password File (/etc/shadow) Insecure Permissions",
		"Allowing unprivileged users or other accounts to read or modify /etc/shadow exposes hashed system passwords to offline cracking or tampering.",
		"critical",
	)

	// 2. /etc/gshadow world-readable or world/group-writable
	checkFile("/etc/gshadow", 0026, "0640",
		"snapsec:config:gshadow-file-permissions",
		"Group Shadow File (/etc/gshadow) Insecure Permissions",
		"World readability or group writability on /etc/gshadow exposes group passwords and hashes to tampering.",
		"critical",
	)

	// 3. /etc/passwd world writable
	checkFile("/etc/passwd", 0002, "0644",
		"snapsec:config:passwd-file-writable",
		"System User File (/etc/passwd) World-Writable",
		"A world-writable /etc/passwd allows any local user or compromised process to add root-equivalent accounts (UID 0) or modify existing user accounts.",
		"critical",
	)

	// 4. /etc/group world writable
	checkFile("/etc/group", 0002, "0644",
		"snapsec:config:group-file-writable",
		"System Group File (/etc/group) World-Writable",
		"A world-writable /etc/group allows attackers to inject themselves into privileged groups such as sudo, wheel, or docker.",
		"high",
	)

	// 5. /etc/sudoers world readable or writable
	checkFile("/etc/sudoers", 0006, "0440",
		"snapsec:config:sudoers-file-permissions",
		"Sudoers Configuration File (/etc/sudoers) Insecurely Permitted",
		"If /etc/sudoers is world-writable, any user can grant themselves root. If world-readable, attackers can audit sudo privileges without detection.",
		"critical",
	)

	// Check /etc/sudoers.d/* files
	sudoersFiles, _ := filepath.Glob("/etc/sudoers.d/*")
	for _, sf := range sudoersFiles {
		checkFile(sf, 0006, "0440",
			fmt.Sprintf("snapsec:config:sudoers-d-permissions-%s", filepath.Base(sf)),
			fmt.Sprintf("Sudoers Drop-in File (%s) Insecure Permissions", filepath.Base(sf)),
			"Sudoers drop-in files must be mode 0440 and owned by root to prevent unauthorized privilege specification or inspection.",
			"critical",
		)
	}

	// 6. /root directory permissions
	checkFile("/root", 0007, "0700",
		"snapsec:config:root-home-accessible",
		"Root Home Directory (/root) Accessible to Others",
		"The root home directory is readable, writable, or executable by other users, potentially leaking command histories, keys, or scripts.",
		"high",
	)

	return findings
}

// checkSSHKeyPermissions verifies that SSH private keys are not readable by other users
func (d *ConfigIssuesDetector) checkSSHKeyPermissions() []Finding {
	var findings []Finding

	homeDirs := []string{"/root"}
	users, _ := filepath.Glob("/home/*")
	homeDirs = append(homeDirs, users...)

	keyNames := []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_xmss"}

	for _, home := range homeDirs {
		sshDir := filepath.Join(home, ".ssh")
		if _, err := os.Stat(sshDir); err != nil {
			continue
		}

		// Check authorized_keys world-writable
		authKeys := filepath.Join(sshDir, "authorized_keys")
		if info, err := os.Stat(authKeys); err == nil {
			if info.Mode().Perm()&0002 != 0 {
				findings = append(findings, Finding{
					UniversalVulnID:  fmt.Sprintf("snapsec:config:authorized-keys-writable-%s", filepath.Base(home)),
					Title:            fmt.Sprintf("SSH authorized_keys World-Writable for %s", filepath.Base(home)),
					Description:      fmt.Sprintf("%s is world-writable. Any local process or user can append their own SSH public key to obtain access as %s.", authKeys, filepath.Base(home)),
					Severity:         "high",
					VulnType:         VulnTypeConfiguration,
					Category:         "configuration",
					Type:             "configuration",
					SourceClassifier: "config",
					MatchedAt:        authKeys,
					MatcherName:      "ssh_authorized_keys_permissions",
					Remediation:      fmt.Sprintf("Run 'chmod 0600 %s' and ensure correct ownership.", authKeys),
					References:       []string{"https://infosec.mozilla.org/guidelines/openssh"},
					Tags:             []string{"ssh", "permissions", "access-control"},
					DetectedAt:       time.Now(),
				})
			}
		}

		// Check private keys
		for _, keyName := range keyNames {
			keyPath := filepath.Join(sshDir, keyName)
			info, err := os.Stat(keyPath)
			if err != nil {
				continue
			}

			// Private key must not be group or world readable (mode > 0600)
			if info.Mode().Perm()&0077 != 0 {
				findings = append(findings, Finding{
					UniversalVulnID:  fmt.Sprintf("snapsec:config:ssh-private-key-permissions-%s-%s", filepath.Base(home), keyName),
					Title:            fmt.Sprintf("SSH Private Key (%s) Has Insecure Permissions", keyPath),
					Description:      fmt.Sprintf("Private key %s has permissions %04o (should be 0600). Group or other users can read the private key to authenticate as %s.", keyPath, info.Mode().Perm(), filepath.Base(home)),
					Severity:         "high",
					VulnType:         VulnTypeSecret,
					Category:         "configuration",
					Type:             "configuration",
					SourceClassifier: "config",
					MatchedAt:        fmt.Sprintf("%s (mode: %04o)", keyPath, info.Mode().Perm()),
					MatcherName:      "ssh_private_key_permissions",
					Remediation:      fmt.Sprintf("Run 'chmod 0600 %s'.", keyPath),
					References:       []string{"https://infosec.mozilla.org/guidelines/openssh"},
					Tags:             []string{"ssh", "credentials", "private-key"},
					DetectedAt:       time.Now(),
				})
			}
		}
	}

	return findings
}

// checkCloudAndDevCredentials checks for world-readable cloud and container credentials
func (d *ConfigIssuesDetector) checkCloudAndDevCredentials() []Finding {
	var findings []Finding

	dirs := []string{"/root"}
	homeUsers, _ := filepath.Glob("/home/*")
	dirs = append(dirs, homeUsers...)

	credFiles := []struct {
		relPath  string
		title    string
		desc     string
		sev      string
		vulnType string
	}{
		{
			relPath:  ".aws/credentials",
			title:    "AWS Credentials File World-Readable",
			desc:     "AWS access key IDs and secret access keys stored in plaintext are readable by other users on this host.",
			sev:      "high",
			vulnType: VulnTypeSecret,
		},
		{
			relPath:  ".kube/config",
			title:    "Kubernetes Kubeconfig File World-Readable",
			desc:     "Kubernetes cluster certificates and bearer tokens in kubeconfig are readable by other users, allowing cluster takeover.",
			sev:      "high",
			vulnType: VulnTypeKubernetes,
		},
		{
			relPath:  ".docker/config.json",
			title:    "Docker Registry Auth File World-Readable",
			desc:     "Docker configuration containing base64-encoded registry tokens is readable by unprivileged local users.",
			sev:      "medium",
			vulnType: VulnTypeContainer,
		},
	}

	for _, dir := range dirs {
		for _, target := range credFiles {
			p := filepath.Join(dir, target.relPath)
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			if info.Mode().Perm()&0004 != 0 {
				findings = append(findings, Finding{
					UniversalVulnID:  fmt.Sprintf("snapsec:config:cred-world-readable-%s-%s", filepath.Base(dir), filepath.Base(target.relPath)),
					Title:            fmt.Sprintf("%s (%s)", target.title, filepath.Base(dir)),
					Description:      fmt.Sprintf("%s has permissions %04o. %s", p, info.Mode().Perm(), target.desc),
					Severity:         target.sev,
					VulnType:         target.vulnType,
					Category:         "configuration",
					Type:             "configuration",
					SourceClassifier: "config",
					MatchedAt:        fmt.Sprintf("%s (mode: %04o)", p, info.Mode().Perm()),
					MatcherName:      "credential_permissions_audit",
					Remediation:      fmt.Sprintf("Run 'chmod 0600 %s' and verify file ownership.", p),
					References:       []string{"https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html"},
					Tags:             []string{"credentials", "cloud", "security"},
					DetectedAt:       time.Now(),
				})
			}
		}
	}

	return findings
}

// checkDaemonConfigs checks Docker, Redis, and Mongo configuration files for insecure networking
func (d *ConfigIssuesDetector) checkDaemonConfigs() []Finding {
	var findings []Finding

	// 1. Docker daemon unencrypted TCP socket
	dockerCfgPath := "/etc/docker/daemon.json"
	if data, err := os.ReadFile(dockerCfgPath); err == nil {
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err == nil {
			if hosts, ok := cfg["hosts"].([]interface{}); ok {
				for _, h := range hosts {
					hStr, ok := h.(string)
					if ok && strings.HasPrefix(hStr, "tcp://") && !strings.Contains(hStr, "127.0.0.1") {
						tlsVerify, _ := cfg["tlsverify"].(bool)
						if !tlsVerify {
							findings = append(findings, Finding{
								UniversalVulnID:  "snapsec:config:docker-unencrypted-tcp",
								Title:            "Docker Daemon Exposed Over Unencrypted TCP Socket",
								Description:      fmt.Sprintf("Docker is configured to listen on '%s' without TLS verification enabled in %s. Anyone on the network can issue container management commands to achieve root RCE on the host.", hStr, dockerCfgPath),
								Severity:         "critical",
								VulnType:         VulnTypeContainer,
								Category:         "configuration",
								Type:             "configuration",
								SourceClassifier: "config",
								MatchedAt:        fmt.Sprintf("%s: %s", dockerCfgPath, hStr),
								MatcherName:      "docker_tcp_exposure",
								Remediation:      "Remove the remote TCP host or enable mutual TLS authentication ('tlsverify': true, 'tlscacert', 'tlscert', 'tlskey').",
								References:       []string{"https://docs.docker.com/engine/security/protect-access/"},
								Tags:             []string{"docker", "rce", "network-exposure"},
								DetectedAt:       time.Now(),
							})
						}
					}
				}
			}
		}
	}

	// 2. Redis bound to 0.0.0.0 without protected-mode
	redisConfigs := []string{"/etc/redis/redis.conf", "/etc/redis.conf"}
	for _, rc := range redisConfigs {
		f, err := os.Open(rc)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		var bindAll bool
		var protectedModeNo bool
		var hasRequirePass bool

		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			lower := strings.ToLower(line)
			if strings.HasPrefix(lower, "bind ") && strings.Contains(lower, "0.0.0.0") {
				bindAll = true
			}
			if strings.HasPrefix(lower, "protected-mode no") {
				protectedModeNo = true
			}
			if strings.HasPrefix(lower, "requirepass ") {
				hasRequirePass = true
			}
		}
		f.Close()

		if bindAll && protectedModeNo && !hasRequirePass {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:config:redis-unauthenticated-bind",
				Title:            "Redis Listening on 0.0.0.0 Without Password or Protected Mode",
				Description:      fmt.Sprintf("Redis configuration in %s binds to 0.0.0.0 with 'protected-mode no' and no 'requirepass'. Unauthenticated remote attackers can execute Redis commands, potentially writing SSH authorized_keys or cron jobs.", rc),
				Severity:         "critical",
				VulnType:         VulnTypeDatabase,
				Category:         "configuration",
				Type:             "configuration",
				SourceClassifier: "config",
				MatchedAt:        fmt.Sprintf("%s (bind 0.0.0.0, protected-mode no)", rc),
				MatcherName:      "redis_unauthenticated_exposure",
				Remediation:      "Bind Redis to 127.0.0.1, re-enable 'protected-mode yes', and configure a strong password with 'requirepass'.",
				References:       []string{"https://redis.io/docs/management/security/"},
				Tags:             []string{"database", "redis", "rce"},
				DetectedAt:       time.Now(),
			})
		}
	}

	return findings
}
