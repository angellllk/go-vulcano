package plugin

import (
	"encoding/json"
	"errors"
	"github.com/sirupsen/logrus"
	"go-vulcano/database"
	dns "go-vulcano/dns-resolver"
	"go-vulcano/models"
	ps "go-vulcano/port-scanner"
	it "go-vulcano/web-scanner"
	"gorm.io/datatypes"
	"strings"
	"sync"
	"time"
)

// Manager defines the Plugin Manager containing all the plugins.
type Manager struct {
	plugins []Plugin     // plugins defines the Plugins handled by the Manager.
	db      *database.DB // db defines the SQLite database connection.
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

	if settings.PluginsDB.DNSResolver {
		m.Add(&dns.DNSResolver{})
	}

	if settings.PluginsDB.WebScanner {
		m.Add(&it.WebScanner{})
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

func (m *Manager) trimAndParseTarget(target string) (models.TargetInfo, error) {
	targetURL := strings.TrimSpace(target)
	ti, err := ParseTargetInfo(targetURL)
	if err != nil {
		// TODO: Error handling through channels
		logrus.Errorf("failed to parse info: %v", err)
		return models.TargetInfo{}, err
	}
	return ti, nil
}

// runPluginsInParallel runs a parallel scan using all the available plugins.
func (m *Manager) runPluginsInParallel(target *models.TargetInfo, wg *sync.WaitGroup) (models.ScanResult, error) {
	defer wg.Done()

	start := time.Now()
	logrus.Infof("Scanning target: %s", target.FullURL)

	// Run plugins
	dto, err := m.runAll(target)
	if err != nil {
		// TODO: Error handling through channels
		logrus.Errorf("failed to run plugin: %v", err)
		return models.ScanResult{}, err
	}

	// Basic metrics for completion time
	elapsed := time.Since(start)

	var ret models.ScanResult
	ret.Fill(dto)
	ret.Duration = elapsed.String()

	return ret, nil
}

// Scan triggers a parallel scan over the targets.
func (m *Manager) Scan(targets []string) []models.ScanResult {
	var results []models.ScanResult

	// Define concurrency controls
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Iterate over targets
	for _, t := range targets {
		ti, err := m.trimAndParseTarget(t)
		if err != nil {
			continue
		}

		// Increment WaitGroup counter per goroutine
		wg.Add(1)

		// Start parallel run
		go func(target *models.TargetInfo) {
			ret, err := m.runPluginsInParallel(target, &wg)
			if err != nil {
				return
			}

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

// runAll calls for all the available Plugins.
func (m *Manager) runAll(target *models.TargetInfo) (*models.DTO, error) {
	partials := make([]*models.DTO, len(m.plugins))
	e := make([]error, len(m.plugins))

	var wg sync.WaitGroup
	var mu sync.Mutex

	for i, p := range m.plugins {
		wg.Add(1)
		go func(idx int, p Plugin) {
			defer wg.Done()

			dto, err := p.Run(target)
			if err != nil {
				e[idx] = err
				return
			}

			mu.Lock()
			partials[idx] = dto
			mu.Unlock()
		}(i, p)
	}

	wg.Wait()

	var ret models.DTO
	for _, pr := range partials {
		if pr == nil {
			continue
		}
		ret.Ports = append(ret.Ports, pr.Ports...)
		ret.DNS = append(ret.DNS, pr.DNS...)
		ret.Subdomains = append(ret.Subdomains, pr.Subdomains...)
		ret.Vulnerabilities = append(ret.Vulnerabilities, pr.Vulnerabilities...)
	}

	ret.Target = target.Domain
	return &ret, nil
}

// Settings sets up a plugin with new settings.
func (m *Manager) Settings(settings models.SettingsAPI) error {
	var names []string

	var dbSettings database.SettingsDB

	// Add or remove plugin based on settings
	if settings.Plugins.PortScanner {
		if m.Get(PortScanner) == nil {
			m.Add(&ps.PortScanner{})
		}

		names = append(names, PortScanner)
		dbSettings.PSConfigDB = database.PSConfigDB{
			StartPort:   settings.Config.StartPort,
			EndPort:     settings.Config.EndPort,
			Timeout:     settings.Config.Timeout,
			MinWorkers:  settings.Config.MinWorkers,
			MaxWorkers:  settings.Config.MaxWorkers,
			IdleTimeout: settings.Config.IdleTimeout,
		}
	} else {
		m.Remove(PortScanner)
	}

	if settings.Plugins.DNSResolver {
		if m.Get(DNSResolver) == nil {
			m.Add(&dns.DNSResolver{})
		}
	} else {
		m.Remove(DNSResolver)
	}

	if settings.Plugins.WebScanner {
		if m.Get(WebScanner) == nil {
			m.Add(&it.WebScanner{})
		}
	} else {
		m.Remove(WebScanner)
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
	dbSettings.PluginsDB = database.PluginsDB{
		PortScanner: settings.Plugins.PortScanner,
		DNSResolver: settings.Plugins.DNSResolver,
		WebScanner:  settings.Plugins.WebScanner,
	}
	if err := m.db.UpdateSettings(dbSettings); err != nil {
		return err
	}

	return nil
}

// SaveScan records the ScanResult in database.
func (m *Manager) SaveScan(data []models.ScanResult) error {
	for _, d := range data {
		portsJson, err := json.Marshal(d.Ports)
		if err != nil {
			return err
		}
		dnsJson, err := json.Marshal(d.DNS)
		if err != nil {
			return err
		}

		var subdomains []database.SubdomainDB
		for _, s := range d.Subdomains {
			ipJson, err := json.Marshal(s.IPs)
			if err != nil {
				return err
			}
			subdomainDto := database.SubdomainDB{
				Name: s.Name,
				IPs:  ipJson,
			}
			subdomains = append(subdomains, subdomainDto)
		}

		scanResult := database.ScanResultDB{
			Target:          d.Target,
			Duration:        d.Duration,
			Ports:           datatypes.JSON(portsJson),
			DNS:             datatypes.JSON(dnsJson),
			Subdomains:      subdomains,
			Vulnerabilities: nil,
		}

		if err = m.db.SaveScan(&scanResult); err != nil {
			return err
		}
	}
	return nil
}
