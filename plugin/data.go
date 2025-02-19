package plugin

import (
	"errors"
	"go-vulcano/models"
	"net/url"
)

const PortScanner = "Port Scanner"
const DNSResolver = "DNS Resolver"

// ParseTargetInfo parses a URL string into a TargetInfo structure.
func ParseTargetInfo(rawURL string) (models.TargetInfo, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return models.TargetInfo{}, err
	}

	domain := u.Hostname()
	if len(domain) == 0 {
		return models.TargetInfo{}, errors.New("invalid domain")
	}

	return models.TargetInfo{
		FullURL: rawURL,
		Domain:  domain,
	}, nil
}

// ScanResult defines the JSON structure for a result of a scan.
type ScanResult struct {
	Target     string      `json:"target,omitempty"`
	Duration   string      `json:"duration,omitempty"`
	Ports      []int       `json:"ports,omitempty"`
	DNS        []string    `json:"dns,omitempty"`
	Subdomains []Subdomain `json:"subdomains,omitempty"`
	//Banners         map[int]string
	Vulnerabilities []Vulnerability `json:"vulns,omitempty"`
}

type Subdomain struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

type Vulnerability struct {
	PluginName  string `json:"plugin_name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// Settings defines settings applicable to plugins
type Settings struct {
	Config  PortScannerConfig `json:"port_scanner"`
	Plugins Plugins           `json:"plugins"`
}

// Plugins defines all the possible plugins that the end user can enable.
type Plugins struct {
	PortScanner bool `json:"port_scanner"`
	DNSResolver bool `json:"dns_resolver"`
	// Add other plugins...
}

// PortScannerConfig defines the configuration parameters used to be used
// by the end-user to redefine settings.
type PortScannerConfig struct {
	StartPort   int `json:"start_port"`
	EndPort     int `json:"end_port"`
	Timeout     int `json:"timeout"`
	MinWorkers  int `json:"min_workers"`
	MaxWorkers  int `json:"max_workers"`
	IdleTimeout int `json:"idle_timeout"`
}
