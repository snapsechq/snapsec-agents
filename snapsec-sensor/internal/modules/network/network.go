package network

import (
	"bufio"
	"os"
	"strings"

	"github.com/shirou/gopsutil/v3/net"
)

type NetworkModule struct{}

type InterfaceData struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac"`
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
	MTU  int      `json:"mtu"`
	State string  `json:"state"`
}

type RouteData struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway"`
	Interface   string `json:"interface"`
}

type NetworkData struct {
	Interfaces []InterfaceData `json:"interfaces"`
	Routes     []RouteData     `json:"routes"`
	DNS        []string        `json:"dns"`
}

func (m *NetworkModule) Name() string {
	return "network"
}

func (m *NetworkModule) Gather() (interface{}, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var intfData []InterfaceData
	for _, i := range interfaces {
		var ipv4, ipv6 []string
		for _, a := range i.Addrs {
			if strings.Contains(a.Addr, ":") {
				ipv6 = append(ipv6, a.Addr)
			} else {
				ipv4 = append(ipv4, a.Addr)
			}
		}

		state := "unknown"
		for _, f := range i.Flags {
			if f == "up" {
				state = "up"
				break
			}
		}

		intfData = append(intfData, InterfaceData{
			Name:  i.Name,
			MAC:   i.HardwareAddr,
			IPv4:  ipv4,
			IPv6:  ipv6,
			MTU:   i.MTU,
			State: state,
		})
	}

	// DNS (Linux specific)
	var dns []string
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "nameserver") {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					dns = append(dns, parts[1])
				}
			}
		}
		f.Close()
	}

	// Routes (Simplified)
	var routes []RouteData
	// In a real scenario, we'd use netlink on Linux or parse 'route print' on Windows.
	// For this agent, we'll leave it as a placeholder or implement basic parsing.

	return NetworkData{
		Interfaces: intfData,
		Routes:     routes,
		DNS:        dns,
	}, nil
}
