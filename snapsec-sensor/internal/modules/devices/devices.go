package devices

import (
	"os/exec"
	"runtime"
	"strings"
)

type DevicesModule struct{}

type USBDevice struct {
	Vendor    string `json:"vendor"`
	Product   string `json:"product"`
	VendorID  string `json:"vendor_id"`
	ProductID string `json:"product_id"`
}

type PCIDevice struct {
	Vendor string `json:"vendor"`
	Device string `json:"device"`
}

type DevicesData struct {
	USB []USBDevice `json:"usb"`
	PCI []PCIDevice `json:"pci"`
}

func (m *DevicesModule) Name() string {
	return "devices"
}

func (m *DevicesModule) Gather() (interface{}, error) {
	var data DevicesData

	if runtime.GOOS == "linux" {
		// USB
		if _, err := exec.LookPath("lsusb"); err == nil {
			out, _ := exec.Command("lsusb").Output()
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				parts := strings.Fields(line)
				if len(parts) >= 6 {
					ids := strings.Split(parts[5], ":")
					vendorID := ids[0]
					productID := ""
					if len(ids) > 1 {
						productID = ids[1]
					}
					data.USB = append(data.USB, USBDevice{
						VendorID:  vendorID,
						ProductID: productID,
						Product:   strings.Join(parts[6:], " "),
					})
				}
			}
		}

		// PCI
		if _, err := exec.LookPath("lspci"); err == nil {
			out, _ := exec.Command("lspci").Output()
			lines := strings.Split(string(out), "\n")
			for _, line := range lines {
				if line == "" {
					continue
				}
				parts := strings.SplitN(line, ": ", 2)
				if len(parts) > 1 {
					data.PCI = append(data.PCI, PCIDevice{
						Device: parts[1],
					})
				}
			}
		}
	}

	return data, nil
}
