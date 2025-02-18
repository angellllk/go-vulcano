package core

import (
	"encoding/json"
	"github.com/sirupsen/logrus"
	"go-vscan/core/handler"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ScanRequest defines the JSON structure for incoming scan requests.
type ScanRequest struct {
	Targets []string `json:"targets"` // List of target URLs.
	Mode    string   `json:"mode"`    // Scan mode: "tcp", "syn", "banner", etc.
}

// ScanResponse defines the JSON structure for scan responses.
type ScanResponse struct {
	Results []ScanResult `json:"scan_results"`
	Error   string       `json:"error,omitempty"`
}

type EnabledPluginsResponse struct {
	Plugins int `json:"plugins"`
}

// Plugins defines all the possible plugins that the end user can enable.
type Plugins struct {
	PortScanner bool `json:"port_scanner"`
	DNSResolver bool `json:"dns_resolver"`
	// Add other plugins...
}

// Settings defines the possible configurations that end users can set.
type Settings struct {
	PSConfig PortScannerConfig `json:"port_scanner"`
	Plugins  Plugins           `json:"plugins"`
}

func settingsHandler(pm *PluginManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var settings Settings

		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&settings); err != nil {
			http.Error(w, "Invalid settings payload", http.StatusBadRequest)
			return
		}

		var names []string

		// Check if plugin is already in use
		if settings.Plugins.PortScanner {
			if pm.GetPluginByName(portScanner) == nil {
				if err := pm.AddPlugin(&PortScanner{}); err != nil {
					http.Error(w, "Error updating settings", http.StatusInternalServerError)
				}
				names = append(names, portScanner)
			}
		} else {
			pm.RemovePlugin(portScanner)
		}

		if settings.Plugins.DNSResolver {
			if pm.GetPluginByName(dnsResolver) == nil {
				if err := pm.AddPlugin(&DNSResolver{}); err != nil {
					http.Error(w, "Error updating settings", http.StatusInternalServerError)
				}
			}
		} else {
			pm.RemovePlugin(dnsResolver)
		}

		// Configure selected
		for _, name := range names {
			plugin := pm.GetPluginByName(name)
			if plugin == nil {
				http.Error(w, "Plugin not found", http.StatusNotFound)
				return
			}

			switch name {
			case portScanner:
				ps, ok := plugin.(*PortScanner)
				if !ok {
					http.Error(w, "Invalid plugin type", http.StatusInternalServerError)
					return
				}

				if err := ps.Configure(settings.PSConfig); err != nil {
					http.Error(w, "Error configuring plugin", http.StatusInternalServerError)
					return
				}
			}
		}
	}
}

// scanHandler processes the scan requests.
func scanHandler(pm *PluginManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req ScanRequest
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&req); err != nil {
			http.Error(w, "Invalid request payload", http.StatusBadRequest)
			return
		}

		if len(req.Targets) == 0 {
			http.Error(w, "No targets provided", http.StatusBadRequest)
			return
		}

		var results []ScanResult
		var wg sync.WaitGroup
		var scanMu sync.Mutex

		var errMsg string

		for _, t := range req.Targets {
			targetURL := strings.TrimSpace(t)
			// Parse the target URL into TargetInfo.
			ti, err := ParseTargetInfo(targetURL)
			if err != nil {
				scanMu.Lock()
				errMsg = err.Error()
				scanMu.Unlock()
				continue
			}

			wg.Add(1)
			go func(target TargetInfo) {
				defer wg.Done()
				logrus.Infof("Scanning target: %s", target.FullURL)

				start := time.Now()

				// Run port scanning.
				result, err := pm.RunAll(&target)
				if err != nil {
					scanMu.Lock()
					errMsg = err.Error()
					scanMu.Unlock()
					return
				}

				elapsed := time.Since(start)
				result.Duration = elapsed.String()
				result.Target = target.FullURL

				scanMu.Lock()
				results = append(results, *result)
				scanMu.Unlock()
			}(ti)
		}

		wg.Wait()

		resp := ScanResponse{
			Results: results,
			Error:   errMsg,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// corsMiddleware adds the necessary CORS headers to each response.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		// Handle preflight requests.
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// StartServer starts the HTTP server.
func StartServer() {
	logrus.SetLevel(logrus.DebugLevel)

	pm := NewPluginManager()

	mux := http.NewServeMux()
	mux.HandleFunc("/scan", scanHandler(pm))
	mux.HandleFunc("/settings", settingsHandler(pm))
	mux.HandleFunc("/plugins", handler.EnabledPluginsHandler(pm))
	// Wrap the mux with the CORS middleware.
	handler := corsMiddleware(mux)

	logrus.Info("Backend server started on :8080")
	http.ListenAndServe(":8080", handler)
}
