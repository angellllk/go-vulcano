package port_scanner

// Config defines the configuration parameters used to be used
// by the end-user to redefine settings.
type Config struct {
	StartPort   int `json:"start_port"`
	EndPort     int `json:"end_port"`
	Timeout     int `json:"timeout"`
	MinWorkers  int `json:"min_workers"`
	MaxWorkers  int `json:"max_workers"`
	IdleTimeout int `json:"idle_timeout"`
}
