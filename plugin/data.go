package plugin

import (
	"context"
	"errors"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
	"net"
	"net/url"
	"time"
)

const PortScanner = "Port Scanner"
const DNSResolver = "DNS Resolver"
const WebScanner = "Web Scanner"

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

	// Resolve the domain to an IP address
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ips, err := net.DefaultResolver.LookupHost(ctx, domain)
	if err != nil || len(ips) == 0 {
		logrus.Errorf("Failed to resolve host %s: %v", domain, err)
		return models.TargetInfo{}, err
	}
	targetIP := net.ParseIP(ips[0])

	return models.TargetInfo{
		IP:      targetIP,
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
	Config  models.PortScannerConfig `json:"port_scanner"`
	Plugins Plugins                  `json:"plugins"`
}

// Plugins defines all the possible plugins that the end user can enable.
type Plugins struct {
	PortScanner bool `json:"port_scanner"`
	DNSResolver bool `json:"dns_resolver"`
	// Add other plugins...
}
