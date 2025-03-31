package database

import (
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type SettingsDB struct {
	PSConfigDB
	PluginsDB
}

type PSConfigDB struct {
	gorm.Model
	StartPort   int `gorm:"start_port"`
	EndPort     int `gorm:"end_port"`
	Timeout     int `gorm:"timeout"`
	MinWorkers  int `gorm:"min_workers"`
	MaxWorkers  int `gorm:"max_workers"`
	IdleTimeout int `gorm:"idle_timeout"`
	RateLimit   int `gorm:"rate_limit"`
}

type PluginsDB struct {
	gorm.Model
	PortScanner bool `gorm:"port_scanner"`
	DNSResolver bool `gorm:"dns_resolver"`
	WebScanner  bool `gorm:"web_scanner"`
}

type ScanResultDB struct {
	gorm.Model
	Target          string            `gorm:"column:target;not null"`
	Duration        string            `gorm:"column:duration"`
	Ports           datatypes.JSON    `gorm:"column:ports"`
	DNS             datatypes.JSON    `gorm:"column:dns"`
	Subdomains      []SubdomainDB     `gorm:"foreignKey:ScanResultID;constraint:OnDelete:CASCADE;"`
	Vulnerabilities []VulnerabilityDB `gorm:"foreignKey:ScanResultID;constraint:OnDelete:CASCADE;"`
}

type SubdomainDB struct {
	gorm.Model
	ScanResultID uint           `gorm:"column:scan_result_id;not null"`
	Name         string         `gorm:"column:name;not null"`
	IPs          datatypes.JSON `gorm:"column:ips"`
}

type VulnerabilityDB struct {
	gorm.Model
	ScanResultID uint   `gorm:"column:scan_result_id;not null"`
	PluginName   string `gorm:"column:plugin_name;not null"`
	Title        string `gorm:"column:title;not null"`
	Severity     string `gorm:"column:severity;not null"`
	Description  string `gorm:"column:description"`
	Evidence     string `gorm:"column:evidence"`
}
