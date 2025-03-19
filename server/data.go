package server

import "go-vulcano/models"

// response defines the basic HTTP response returned by the server.
type response struct {
	Error   bool   `json:"error"`
	Message string `json:"message"`
}

// ScanRequestAPI defines the JSON structure for incoming scan requests.
type ScanRequestAPI struct {
	Targets []string `json:"targets"`
	Mode    string   `json:"mode"`
}

func (sr *ScanRequestAPI) Validate() bool {
	if len(sr.Targets) == 0 || len(sr.Mode) == 0 {
		return false
	}
	if sr.Mode != "tcp" && sr.Mode != "syn" {
		return false
	}
	return true
}

// ScanResponse defines the JSON structure for scan responses.
type ScanResponse struct {
	Results []models.ScanResult `json:"scan_results"`
}

type EnabledPlugins struct {
	Plugins int `json:"plugins"`
}
