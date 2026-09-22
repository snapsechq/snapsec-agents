package packages

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

type PackagesModule struct{}

// PackageInfo carries the metadata AIM's CPE resolver uses. Beyond name/version,
// we collect authoritative vendor metadata per platform (dpkg Maintainer/Homepage,
// rpm Vendor/URL, Windows registry Publisher, macOS bundle identifier) so the
// backend can derive an accurate CPE vendor instead of guessing from the name.
type PackageInfo struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Arch        string `json:"arch,omitempty"`
	Vendor      string `json:"vendor,omitempty"`
	Publisher   string `json:"publisher,omitempty"`
	Maintainer  string `json:"maintainer,omitempty"`
	Homepage    string `json:"homepage,omitempty"`
	Product     string `json:"product,omitempty"`
	InstalledAt string `json:"installed_at,omitempty"`
}

type PackagesData struct {
	Type  string        `json:"type"`
	Count int           `json:"count"`
	List  []PackageInfo `json:"list"`
}

func (m *PackagesModule) Name() string {
	return "packages"
}

func (m *PackagesModule) Gather() (interface{}, error) {
	var pkgType string
	var list []PackageInfo

	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("dpkg-query"); err == nil {
			pkgType = "apt"
			list = gatherDpkg()
		} else if _, err := exec.LookPath("rpm"); err == nil {
			pkgType = "rpm"
			list = gatherRpm()
		}
	case "darwin":
		pkgType = "macos"
		list = gatherMacApps()
		list = append(list, gatherBrew()...)
	case "windows":
		pkgType = "windows"
		list = gatherWindows()
	}

	return PackagesData{
		Type:  pkgType,
		Count: len(list),
		List:  list,
	}, nil
}

// clean drops placeholder values some package managers emit (e.g. rpm "(none)").
func clean(s string) string {
	s = strings.TrimSpace(s)
	if s == "(none)" || s == "(null)" {
		return ""
	}
	return s
}

// --- Linux: dpkg (Debian/Ubuntu) ---
// Tab-delimited so Maintainer/Homepage (which contain spaces) parse cleanly.
func gatherDpkg() []PackageInfo {
	out, _ := exec.Command("dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${Maintainer}\t${Homepage}\n").Output()

	var pkgs []PackageInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		p := PackageInfo{Name: clean(field(f, 0)), Version: clean(field(f, 1)), Arch: clean(field(f, 2))}
		p.Maintainer = clean(field(f, 3))
		p.Homepage = clean(field(f, 4))
		if p.Name != "" {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

// --- Linux: rpm (RHEL/Fedora/SUSE) ---
func gatherRpm() []PackageInfo {
	out, _ := exec.Command("rpm", "-qa", "--queryformat",
		"%{NAME}\t%{VERSION}\t%{ARCH}\t%{VENDOR}\t%{URL}\n").Output()

	var pkgs []PackageInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		p := PackageInfo{Name: clean(field(f, 0)), Version: clean(field(f, 1)), Arch: clean(field(f, 2))}
		p.Vendor = clean(field(f, 3))
		p.Homepage = clean(field(f, 4))
		if p.Name != "" {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

// --- macOS: installed applications (Info.plist) ---
// The bundle identifier (e.g. com.google.Chrome) yields an authoritative vendor.
func gatherMacApps() []PackageInfo {
	var pkgs []PackageInfo
	for _, dir := range []string{"/Applications", "/System/Applications"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".app") {
				continue
			}
			plist := filepath.Join(dir, e.Name(), "Contents", "Info.plist")
			name := readDefault(plist, "CFBundleName")
			if name == "" {
				name = strings.TrimSuffix(e.Name(), ".app")
			}
			version := readDefault(plist, "CFBundleShortVersionString")
			bundleID := readDefault(plist, "CFBundleIdentifier")
			pkgs = append(pkgs, PackageInfo{
				Name:    name,
				Version: version,
				Vendor:  vendorFromBundleID(bundleID),
			})
		}
	}
	return pkgs
}

func readDefault(plist, key string) string {
	out, err := exec.Command("defaults", "read", plist, key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// vendorFromBundleID maps a reverse-DNS bundle id to a vendor token:
// "com.google.Chrome" -> "google", "org.mozilla.firefox" -> "mozilla".
func vendorFromBundleID(id string) string {
	parts := strings.Split(id, ".")
	if len(parts) >= 2 {
		switch strings.ToLower(parts[0]) {
		case "com", "org", "io", "net", "co", "app":
			return strings.ToLower(parts[1])
		}
	}
	return ""
}

// --- macOS: Homebrew (supplements GUI apps) ---
func gatherBrew() []PackageInfo {
	if _, err := exec.LookPath("brew"); err != nil {
		return nil
	}
	out, _ := exec.Command("brew", "list", "--versions").Output()
	var pkgs []PackageInfo
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) >= 2 {
			pkgs = append(pkgs, PackageInfo{Name: f[0], Version: f[1]})
		}
	}
	return pkgs
}

// --- Windows: registry uninstall entries (64-bit + 32-bit) ---
// Reports DisplayName/DisplayVersion/Publisher/URLInfoAbout. Uses "||" as a
// field separator to avoid clashing with spaces in names/publishers.
func gatherWindows() []PackageInfo {
	const ps = `$ErrorActionPreference='SilentlyContinue';` +
		`$paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',` +
		`'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',` +
		`'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*');` +
		`Get-ItemProperty $paths | Where-Object { $_.DisplayName } | ForEach-Object {` +
		`'{0}||{1}||{2}||{3}' -f $_.DisplayName,$_.DisplayVersion,$_.Publisher,$_.URLInfoAbout }`

	out, _ := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", ps).Output()

	var pkgs []PackageInfo
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "||")
		p := PackageInfo{Name: clean(field(f, 0)), Version: clean(field(f, 1))}
		p.Publisher = clean(field(f, 2))
		p.Homepage = clean(field(f, 3))
		if p.Name != "" {
			pkgs = append(pkgs, p)
		}
	}
	return pkgs
}

func field(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}
