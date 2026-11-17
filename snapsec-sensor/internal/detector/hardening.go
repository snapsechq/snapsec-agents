package detector

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// HardeningDetector audits system hardening settings against industry benchmarks (CIS / Lynis).
type HardeningDetector struct{}

func NewHardeningDetector() *HardeningDetector {
	return &HardeningDetector{}
}

func (d *HardeningDetector) Name() string {
	return "hardening"
}

func (d *HardeningDetector) Category() string {
	return "hardening"
}

func (d *HardeningDetector) Run(ctx context.Context) ([]Finding, error) {
	var findings []Finding

	if runtime.GOOS == "linux" {
		findings = append(findings, d.checkSSHHardening()...)
		findings = append(findings, d.checkKernelSysctl()...)
		findings = append(findings, d.checkLSMAndFirewall()...)
	}

	for i := range findings {
		if findings[i].VulnType == "" {
			findings[i].VulnType = VulnTypeConfiguration
		}
	}

	return findings, nil
}

// checkSSHHardening parses sshd config files for insecure server settings
func (d *HardeningDetector) checkSSHHardening() []Finding {
	var findings []Finding
	configFiles := []string{"/etc/ssh/sshd_config"}

	// Also check include directory sshd_config.d
	matches, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	configFiles = append(configFiles, matches...)

	settings := make(map[string]string)

	for _, cfg := range configFiles {
		file, err := os.Open(cfg)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				key := strings.ToLower(parts[0])
				val := strings.ToLower(parts[1])
				// First setting wins in OpenSSH config evaluation
				if _, exists := settings[key]; !exists {
					settings[key] = val
				}
			}
		}
		file.Close()
	}

	// 1. Check PermitRootLogin
	if val, ok := settings["permitrootlogin"]; ok {
		if val == "yes" {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:ssh-permit-root-login",
				Title:            "SSH Daemon Allows Direct Root Login",
				Description:      "The SSH daemon is configured with 'PermitRootLogin yes', allowing remote root login attempts which increases exposure to brute-force and credential stuffing attacks.",
				Severity:         "high",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/etc/ssh/sshd_config: PermitRootLogin " + val,
				MatcherName:      "ssh_permit_root_login",
				Remediation:      "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config and restart sshd.",
				References:       []string{"https://infosec.mozilla.org/guidelines/openssh", "https://www.cisecurity.org/benchmark/ubuntu_linux"},
				Tags:             []string{"ssh", "hardening", "access-control"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"setting": "PermitRootLogin", "value": val},
			})
		}
	}

	// 2. Check PermitEmptyPasswords
	if val, ok := settings["permitemptypasswords"]; ok {
		if val == "yes" {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:ssh-empty-passwords",
				Title:            "SSH Daemon Permits Empty Passwords",
				Description:      "The SSH configuration enables 'PermitEmptyPasswords yes', which allows accounts with empty password fields to log in without authentication.",
				Severity:         "critical",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/etc/ssh/sshd_config: PermitEmptyPasswords yes",
				MatcherName:      "ssh_permit_empty_passwords",
				Remediation:      "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd.",
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"ssh", "hardening", "authentication"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"setting": "PermitEmptyPasswords", "value": val},
			})
		}
	}

	// 3. Check PasswordAuthentication
	if val, ok := settings["passwordauthentication"]; ok {
		if val == "yes" {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:ssh-password-authentication",
				Title:            "SSH Password Authentication Enabled",
				Description:      "Password authentication is enabled for SSH. Public key authentication is recommended over passwords to eliminate credential guessing risks.",
				Severity:         "medium",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/etc/ssh/sshd_config: PasswordAuthentication yes",
				MatcherName:      "ssh_password_authentication",
				Remediation:      "Ensure SSH public keys are configured for required users, then set 'PasswordAuthentication no' in /etc/ssh/sshd_config.",
				References:       []string{"https://infosec.mozilla.org/guidelines/openssh"},
				Tags:             []string{"ssh", "hardening", "passwords"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"setting": "PasswordAuthentication", "value": val},
			})
		}
	}

	// 4. Check X11Forwarding
	if val, ok := settings["x11forwarding"]; ok {
		if val == "yes" {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:ssh-x11-forwarding",
				Title:            "SSH X11 Forwarding Enabled on Server",
				Description:      "X11 forwarding is enabled in SSH. On headless servers, this creates unnecessary attack surface for keystroke sniffing and window hijacking.",
				Severity:         "low",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/etc/ssh/sshd_config: X11Forwarding yes",
				MatcherName:      "ssh_x11_forwarding",
				Remediation:      "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless explicitly required for GUI applications.",
				References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
				Tags:             []string{"ssh", "hardening"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"setting": "X11Forwarding", "value": val},
			})
		}
	}

	// 5. Check MaxAuthTries
	if val, ok := settings["maxauthtries"]; ok {
		if tries, err := strconv.Atoi(val); err == nil && tries > 4 {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:ssh-max-auth-tries",
				Title:            "SSH MaxAuthTries Configured High",
				Description:      fmt.Sprintf("SSH MaxAuthTries is set to %d. A lower threshold (4 or fewer) limits brute-force attacks before the connection is dropped.", tries),
				Severity:         "low",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/etc/ssh/sshd_config: MaxAuthTries " + val,
				MatcherName:      "ssh_max_auth_tries",
				Remediation:      "Set 'MaxAuthTries 4' in /etc/ssh/sshd_config and restart sshd.",
				References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
				Tags:             []string{"ssh", "hardening", "bruteforce"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"setting": "MaxAuthTries", "value": val},
			})
		}
	}

	return findings
}

// checkKernelSysctl reads /proc/sys runtime parameters for kernel hardening compliance
func (d *HardeningDetector) checkKernelSysctl() []Finding {
	var findings []Finding

	// Helper to read sysctl proc value
	readSysctl := func(path string) (string, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}

	// 1. ASLR (randomize_va_space)
	if val, err := readSysctl("/proc/sys/kernel/randomize_va_space"); err == nil {
		if n, err := strconv.Atoi(val); err == nil && n < 2 {
			findings = append(findings, Finding{
				UniversalVulnID:  "snapsec:hardening:aslr-disabled",
				Title:            "Address Space Layout Randomization (ASLR) Incomplete or Disabled",
				Description:      fmt.Sprintf("kernel.randomize_va_space is set to %s (recommended: 2). Full ASLR randomizes stack, vDSO, shared memory, and data segments, mitigating buffer overflow exploits.", val),
				Severity:         "high",
				Category:         "hardening",
				Type:             "hardening",
				SourceClassifier: "config",
				MatchedAt:        "/proc/sys/kernel/randomize_va_space = " + val,
				MatcherName:      "sysctl_aslr",
				Remediation:      "Add 'kernel.randomize_va_space = 2' to /etc/sysctl.d/99-security.conf and execute 'sysctl -p'.",
				References:       []string{"https://wiki.ubuntu.com/Security/Features#aslr"},
				Tags:             []string{"kernel", "hardening", "memory-protection", "aslr"},
				DetectedAt:       time.Now(),
				Raw:              map[string]interface{}{"sysctl": "kernel.randomize_va_space", "value": val},
			})
		}
	}

	// 2. IP Forwarding (net.ipv4.ip_forward)
	if val, err := readSysctl("/proc/sys/net/ipv4/ip_forward"); err == nil && val == "1" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:ip-forwarding-enabled",
			Title:            "IPv4 Packet Forwarding Enabled",
			Description:      "net.ipv4.ip_forward is set to 1. On hosts that are not dedicated routers, packet forwarding can allow traffic routing between interfaces without authorization.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/net/ipv4/ip_forward = 1",
			MatcherName:      "sysctl_ip_forward",
			Remediation:      "If this host is not a network gateway or container host requiring forwarding, set 'net.ipv4.ip_forward = 0' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
			Tags:             []string{"kernel", "network", "hardening"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "net.ipv4.ip_forward", "value": val},
		})
	}

	// 3. ICMP Redirects
	if val, err := readSysctl("/proc/sys/net/ipv4/conf/all/accept_redirects"); err == nil && val == "1" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:icmp-redirects-accepted",
			Title:            "ICMP Redirect Acceptance Enabled",
			Description:      "net.ipv4.conf.all.accept_redirects is set to 1. Accepting ICMP redirects can be exploited by an attacker on the local network to manipulate routing tables and perform MITM attacks.",
			Severity:         "low",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/net/ipv4/conf/all/accept_redirects = 1",
			MatcherName:      "sysctl_accept_redirects",
			Remediation:      "Add 'net.ipv4.conf.all.accept_redirects = 0' and 'net.ipv4.conf.default.accept_redirects = 0' to /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
			Tags:             []string{"kernel", "network", "mitm"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "net.ipv4.conf.all.accept_redirects", "value": val},
		})
	}

	// 4. Source Routed Packets
	if val, err := readSysctl("/proc/sys/net/ipv4/conf/all/accept_source_route"); err == nil && val == "1" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:source-route-accepted",
			Title:            "IP Source Routing Accepted",
			Description:      "net.ipv4.conf.all.accept_source_route is enabled. Source routing allows senders to predetermine the network route, bypassing network security boundaries and firewall rules.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/net/ipv4/conf/all/accept_source_route = 1",
			MatcherName:      "sysctl_accept_source_route",
			Remediation:      "Set 'net.ipv4.conf.all.accept_source_route = 0' and 'net.ipv4.conf.default.accept_source_route = 0' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
			Tags:             []string{"kernel", "network", "routing"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "net.ipv4.conf.all.accept_source_route", "value": val},
		})
	}

	// 5. TCP SYN Cookies
	if val, err := readSysctl("/proc/sys/net/ipv4/tcp_syncookies"); err == nil && val == "0" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:tcp-syncookies-disabled",
			Title:            "TCP SYN Cookies Protection Disabled",
			Description:      "net.ipv4.tcp_syncookies is set to 0. Without SYN cookies, the host is vulnerable to SYN flood denial-of-service (DoS) attacks exhausting connection state tables.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/net/ipv4/tcp_syncookies = 0",
			MatcherName:      "sysctl_tcp_syncookies",
			Remediation:      "Set 'net.ipv4.tcp_syncookies = 1' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
			Tags:             []string{"kernel", "dos", "hardening"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "net.ipv4.tcp_syncookies", "value": val},
		})
	}

	// 6. SUID Core Dumps (fs.suid_dumpable)
	if val, err := readSysctl("/proc/sys/fs/suid_dumpable"); err == nil && val != "0" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:suid-dumpable-enabled",
			Title:            "Core Dumps for SUID Programs Allowed",
			Description:      fmt.Sprintf("fs.suid_dumpable is set to %s. Allowing SUID binaries to produce core dumps can leak sensitive root credentials or cryptographic keys to disk.", val),
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/fs/suid_dumpable = " + val,
			MatcherName:      "sysctl_suid_dumpable",
			Remediation:      "Set 'fs.suid_dumpable = 0' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
			Tags:             []string{"kernel", "privilege-escalation", "core-dump"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "fs.suid_dumpable", "value": val},
		})
	}

	// 7. Unprivileged eBPF
	if val, err := readSysctl("/proc/sys/kernel/unprivileged_bpf_disabled"); err == nil && val == "0" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:unprivileged-ebpf-allowed",
			Title:            "Unprivileged eBPF Allowed",
			Description:      "kernel.unprivileged_bpf_disabled is 0. Unprivileged users can load eBPF programs, which significantly expands the kernel attack surface and has been the source of multiple local privilege escalations.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/kernel/unprivileged_bpf_disabled = 0",
			MatcherName:      "sysctl_unprivileged_bpf",
			Remediation:      "Set 'kernel.unprivileged_bpf_disabled = 1' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://kernel.org/doc/Documentation/sysctl/kernel.txt"},
			Tags:             []string{"kernel", "ebpf", "privilege-escalation"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "kernel.unprivileged_bpf_disabled", "value": val},
		})
	}

	// 8. Dmesg Restriction
	if val, err := readSysctl("/proc/sys/kernel/dmesg_restrict"); err == nil && val == "0" {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:dmesg-unrestricted",
			Title:            "Kernel Ring Buffer (dmesg) Accessible to Unprivileged Users",
			Description:      "kernel.dmesg_restrict is 0. Unprivileged users can inspect kernel log messages, which can expose kernel memory addresses, hardware signatures, and sensitive debug info.",
			Severity:         "low",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "/proc/sys/kernel/dmesg_restrict = 0",
			MatcherName:      "sysctl_dmesg_restrict",
			Remediation:      "Set 'kernel.dmesg_restrict = 1' in /etc/sysctl.d/99-security.conf.",
			References:       []string{"https://www.cisecurity.org/benchmark/distribution_independent_linux"},
			Tags:             []string{"kernel", "information-disclosure"},
			DetectedAt:       time.Now(),
			Raw:              map[string]interface{}{"sysctl": "kernel.dmesg_restrict", "value": val},
		})
	}

	return findings
}

// checkLSMAndFirewall verifies host firewall and Linux Security Modules (AppArmor / SELinux)
func (d *HardeningDetector) checkLSMAndFirewall() []Finding {
	var findings []Finding

	// Check Firewall (UFW / iptables)
	firewallActive := false
	if _, err := exec.LookPath("ufw"); err == nil {
		out, err := exec.Command("ufw", "status").Output()
		if err == nil && strings.Contains(string(out), "Status: active") {
			firewallActive = true
		}
	} else if _, err := exec.LookPath("iptables"); err == nil {
		out, err := exec.Command("iptables", "-L", "-n").Output()
		// If custom rules exist in INPUT chain
		if err == nil && (strings.Contains(string(out), "ACCEPT") || strings.Contains(string(out), "DROP")) {
			firewallActive = true
		}
	}

	if !firewallActive {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:host-firewall-inactive",
			Title:            "Host-Level Firewall Inactive or Unconfigured",
			Description:      "No active host firewall (UFW, iptables, or nftables) was detected on the system. Exposed network services can be directly accessed from untrusted networks without boundary filtering.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "firewall: inactive",
			MatcherName:      "firewall_status",
			Remediation:      "Enable a host firewall (e.g. 'sudo ufw enable' or configure nftables) and allow only required inbound ports.",
			References:       []string{"https://help.ubuntu.com/community/UFW"},
			Tags:             []string{"firewall", "network", "hardening"},
			DetectedAt:       time.Now(),
		})
	}

	// Check LSM (AppArmor / SELinux)
	lsmActive := false
	if _, err := exec.LookPath("aa-status"); err == nil {
		out, err := exec.Command("aa-status", "--enabled").Output()
		if err == nil && len(out) == 0 {
			lsmActive = true
		}
	} else if _, err := exec.LookPath("sestatus"); err == nil {
		out, err := exec.Command("sestatus").Output()
		if err == nil && strings.Contains(string(out), "SELinux status:                 enabled") &&
			!strings.Contains(string(out), "Current mode:                   permissive") {
			lsmActive = true
		}
	}

	if !lsmActive {
		findings = append(findings, Finding{
			UniversalVulnID:  "snapsec:hardening:lsm-disabled",
			Title:            "Mandatory Access Control (AppArmor / SELinux) Inactive",
			Description:      "No active Linux Security Module (AppArmor or SELinux in enforcing mode) was found. Mandatory access controls enforce process confinement and mitigate zero-day binary compromises.",
			Severity:         "medium",
			Category:         "hardening",
			Type:             "hardening",
			SourceClassifier: "config",
			MatchedAt:        "lsm: disabled or permissive",
			MatcherName:      "lsm_status",
			Remediation:      "Enable AppArmor ('systemctl enable --now apparmor') or SELinux in enforcing mode.",
			References:       []string{"https://www.cisecurity.org/benchmark/ubuntu_linux"},
			Tags:             []string{"selinux", "apparmor", "lsm", "hardening"},
			DetectedAt:       time.Now(),
		})
	}

	return findings
}
