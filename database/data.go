package database

import "gorm.io/gorm"

type Settings struct {
	PSConfig
	PluginsDB
}

type PSConfig struct {
	gorm.Model
	StartPort   int `gorm:"start_port"`
	EndPort     int `gorm:"end_port"`
	Timeout     int `gorm:"timeout"`
	MinWorkers  int `gorm:"min_workers"`
	MaxWorkers  int `gorm:"max_workers"`
	IdleTimeout int `gorm:"idle_timeout"`
}

type PluginsDB struct {
	gorm.Model
	PortScanner bool `gorm:"port_scanner"`
	DNSResolver bool `gorm:"dns_resolver"`
}
