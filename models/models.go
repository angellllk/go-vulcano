package models

// ScanResult defines the JSON structure for a result of a scan.
type ScanResult struct {
	Target     string      `json:"target,omitempty"`
	Duration   string      `json:"duration,omitempty"`
	Ports      []int       `json:"ports,omitempty"`
	DNS        []string    `json:"dns,omitempty"`
	Subdomains []Subdomain `json:"subdomains,omitempty"`
	//Banners         map[int]string
	Vulnerabilities []VulnerabilityDTO `json:"vulns,omitempty"`
}

type Subdomain struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

func (s *ScanResult) Fill(dto *DTO) {
	s.Target = dto.Target
	s.DNS = dto.DNS
	s.Ports = dto.Ports

	if dto.Subdomains != nil {
		s.Subdomains = make([]Subdomain, 0, len(dto.Subdomains))
		for _, sdDTO := range dto.Subdomains {
			s.Subdomains = append(s.Subdomains, Subdomain{
				Name: sdDTO.Name,
				IPs:  sdDTO.IPs,
			})
		}
	}

	if dto.Vulnerabilities != nil {
		s.Vulnerabilities = make([]VulnerabilityDTO, 0, len(dto.Vulnerabilities))
		s.Vulnerabilities = append(s.Vulnerabilities, dto.Vulnerabilities...)
	}
}

// SubdomainDTO defines the Subdomain data to be returned.
type SubdomainDTO struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

// DTO defines the Data Transfer Object structure.
type DTO struct {
	Target     string         `json:"target,omitempty"`
	Duration   string         `json:"duration,omitempty"`
	Ports      []int          `json:"ports,omitempty"`
	DNS        []string       `json:"dns,omitempty"`
	Subdomains []SubdomainDTO `json:"subdomains,omitempty"`
	//Banners    map[int]string
	Vulnerabilities []VulnerabilityDTO `json:"vulns,omitempty"`
}

type VulnerabilityDTO struct {
	PluginName  string `json:"plugin_name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

// SettingsAPI defines the possible configurations that end users can set.
type SettingsAPI struct {
	Config  PortScannerConfig `json:"port_scanner"`
	Plugins Plugins           `json:"plugins"`
}

// Plugins defines all the possible plugins that the end user can enable.
type Plugins struct {
	PortScanner bool `json:"port_scanner"`
	DNSResolver bool `json:"dns_resolver"`
	WebScanner  bool `json:"web_scanner"`
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

// TargetInfo holds information about a target.
type TargetInfo struct {
	FullURL string
	Domain  string
}

// Options defines the options for Plugins.
type Options struct {
	ScanMode string
}
