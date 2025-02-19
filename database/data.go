package database

import "gorm.io/gorm"

type Settings struct {
	PSConfig
	PluginsDB
}

type PSConfig struct {
	gorm.Model
	StartPort   int `db:"start_port"`
	EndPort     int `db:"end_port"`
	Timeout     int `db:"timeout"`
	MinWorkers  int `db:"min_workers"`
	MaxWorkers  int `db:"max_workers"`
	IdleTimeout int `db:"idle_timeout"`
}

type PluginsDB struct {
	gorm.Model
	PortScanner bool `db:"port_scanner"`
}
