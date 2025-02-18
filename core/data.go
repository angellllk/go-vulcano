package core

// ScanResult defines the JSON structure for a result of a scan.
type ScanResult struct {
	Target          string      `json:"target,omitempty"`
	Duration        string      `json:"duration,omitempty"`
	Ports           []int       `json:"ports,omitempty"`
	DNS             []string    `json:"dns,omitempty"`
	Subdomains      []Subdomain `json:"subdomains,omitempty"`
	Banners         map[int]string
	Vulnerabilities []Vulnerability `json:"vulns,omitempty"`
}

type Vulnerability struct {
	PluginName  string `json:"plugin_name"`
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
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
