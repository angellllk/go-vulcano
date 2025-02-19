package plugin

import (
	"errors"
	"github.com/sirupsen/logrus"
	"go-vulcano/database"
	"go-vulcano/models"
	ps "go-vulcano/port-scanner"
	"strings"
	"sync"
	"time"
)

// Manager defines the Plugin Manager containing all the plugins.
type Manager struct {
	plugins []Plugin
	db      *database.DB
}

// NewManager initializes a new *Manager.
func NewManager(db *database.DB) *Manager {
	m := &Manager{
		plugins: make([]Plugin, 0),
		db:      db,
	}

	m.init()
	return m
}

// init initializes the Manager with last used settings.
func (m *Manager) init() {
	settings := m.db.FetchSettings()

	if settings.PluginsDB.PortScanner {
		// Add port scanner plugin
		m.Add(&ps.PortScanner{})
		p := m.Get(PortScanner).(*ps.PortScanner)

		p.Configure(ps.Config{
			StartPort:   settings.StartPort,
			EndPort:     settings.EndPort,
			Timeout:     settings.Timeout,
			MinWorkers:  settings.MinWorkers,
			MaxWorkers:  settings.MaxWorkers,
			IdleTimeout: settings.IdleTimeout,
		})
	}
}

// Add plugs in a new Plugin.
func (m *Manager) Add(p Plugin) {
	m.plugins = append(m.plugins, p)
}

// Remove unplugs a Plugin.
func (m *Manager) Remove(name string) bool {
	var ok bool
	for i, p := range m.plugins {
		if p.Name() == name {
			m.plugins = append(m.plugins[:i], m.plugins[i+1:]...)
			ok = true
		}
	}
	return ok
}

// Count returns the number of active plugins.
func (m *Manager) Count() int {
	return len(m.plugins)
}

// Get retrieves the Plugin.
func (m *Manager) Get(name string) Plugin {
	for _, p := range m.plugins {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

// RunAll calls for all the available Plugins.
func (m *Manager) RunAll(target *models.TargetInfo) (*models.DTO, error) {
	partials := make([]*models.DTO, len(m.plugins))
	e := make([]error, len(m.plugins))

	var wg sync.WaitGroup

	for i, p := range m.plugins {
		wg.Add(1)
		go func(idx int, p Plugin) {
			defer wg.Done()

			dto, err := p.Run(target)
			if err != nil {
				e[idx] = err
				return
			}
			partials[idx] = dto
		}(i, p)
	}

	wg.Wait()

	var ret models.DTO
	for _, pr := range partials {
		ret.Ports = append(ret.Ports, pr.Ports...)
	}

	return &ret, nil
}

// Scan triggers a parallel scan over the targets.
func (m *Manager) Scan(targets []string) []models.ScanResult {
	var results []models.ScanResult

	// Define concurrency controls
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Iterate over targets
	for _, t := range targets {
		// Trim spaces and parse data
		targetURL := strings.TrimSpace(t)
		ti, err := ParseTargetInfo(targetURL)
		if err != nil {
			// TODO: Error handling through channels
			logrus.Errorf("failed to parse info: %v", err)
			continue
		}

		// Increment WaitGroup counter per goroutine
		wg.Add(1)

		// Start goroutine
		go func(target *models.TargetInfo) {
			defer wg.Done()

			start := time.Now()
			logrus.Infof("Scanning target: %s", target.FullURL)

			// Run plugins
			dto, err := m.RunAll(target)
			if err != nil {
				// TODO: Error handling through channels
				logrus.Errorf("failed to run plugin: %v", err)
				return
			}

			// Basic metrics for completion time
			elapsed := time.Since(start)

			var ret models.ScanResult
			ret.Fill(dto)
			ret.Duration = elapsed.String()

			// Save result
			mu.Lock()
			results = append(results, ret)
			mu.Unlock()
		}(&ti)
	}

	// Wait for the goroutines
	wg.Wait()

	return results
}

// Settings sets up a plugin with new settings.
func (m *Manager) Settings(settings models.SettingsAPI) error {
	var names []string

	// Add or remove plugin based on settings
	if settings.Plugins.PortScanner {
		if m.Get(PortScanner) == nil {
			m.Add(&ps.PortScanner{})
			names = append(names, PortScanner)
		}
	} else {
		m.Remove(PortScanner)
	}

	for _, name := range names {
		plugin := m.Get(name)
		if plugin == nil {
			continue
		}

		switch name {
		case PortScanner:
			p, ok := plugin.(*ps.PortScanner)
			if !ok {
				return errors.New("invalid type conversion to *ps.PortScanner")
			}

			// Apply new settings
			p.Configure(ps.Config(settings.Config))
		default:
			return errors.New("invalid plugin provided")
		}
	}

	// Prepare database DTO
	dbSettings := database.Settings{
		PSConfig: database.PSConfig{
			StartPort:   settings.Config.StartPort,
			EndPort:     settings.Config.EndPort,
			Timeout:     settings.Config.Timeout,
			MinWorkers:  settings.Config.MinWorkers,
			MaxWorkers:  settings.Config.MaxWorkers,
			IdleTimeout: settings.Config.IdleTimeout,
		},
		PluginsDB: database.PluginsDB{
			PortScanner: settings.Plugins.PortScanner,
		},
	}
	if err := m.db.UpdateSettings(dbSettings); err != nil {
		return err
	}

	return nil
}
