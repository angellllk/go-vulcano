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
	"net"
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
	m.addPlugins(settings)
}

// addPlugins adds the plugins based on the settings.
func (m *Manager) addPlugins(settings database.SettingsDB) {
	if settings.PortScanner {
		cfg := models.PortScannerConfig{
			StartPort:   settings.StartPort,
			EndPort:     settings.EndPort,
			Timeout:     settings.Timeout,
			MinWorkers:  settings.MinWorkers,
			MaxWorkers:  settings.MaxWorkers,
			IdleTimeout: settings.IdleTimeout,
			RateLimit:   settings.RateLimit,
		}
		cfg.Fill()

		m.Add(&ps.PortScanner{})
		p := m.Get(PortScanner).(*ps.PortScanner)

		p.Configure(cfg)
		err := p.PrepareSyn()
		if err != nil {
			logrus.Fatalf("failed to prepare SYN scan: %v", err)
		}
	}
	if settings.DNSResolver {
		m.Add(&dns.DNSResolver{})
	}
	if settings.WebScanner {
		m.Add(&it.WebScanner{})
	}
}

// Add plugs in a new Plugin.
func (m *Manager) Add(p Plugin) {
	if m.Get(p.Name()) != nil {
		return
	}
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

// trimAndParseTarget parses the target data and returns the TargetInfo.
func (m *Manager) trimAndParseTarget(target string) (models.TargetInfo, error) {
	targetURL := strings.TrimSpace(target)
	ti, err := ParseTargetInfo(targetURL)
	if err != nil {
		ti.IP = net.ParseIP(target)
		if ti.IP == nil {
			logrus.Errorf("failed to parse target data: %v", err)
			return models.TargetInfo{}, err
		}
	}

	return ti, nil
}

// runPluginsInParallel runs a parallel scan using all the available plugins.
func (m *Manager) runPluginsInParallel(target *models.TargetInfo, opts *models.Options, wg *sync.WaitGroup) (models.ScanResult, error) {
	defer wg.Done()

	// Start timer
	start := time.Now()
	logrus.Infof("Scanning target: %s (IP: %s)", target.FullURL, target.IP.String())

	// Run plugins
	dto, err := m.runAll(target, opts)
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
func (m *Manager) Scan(targets []string, mode string) []models.ScanResult {
	var results []models.ScanResult

	// Define concurrency controls
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Save options to use
	opts := models.Options{
		ScanMode: mode,
	}

	// Iterate over targets
	for _, t := range targets {
		ti, err := m.trimAndParseTarget(t)
		if err != nil {
			logrus.Errorf("failed to parse target: %v", err)
			continue
		}

		// Increment WaitGroup counter per goroutine
		wg.Add(1)

		// Start parallel run
		go func(target *models.TargetInfo) {
			ret, err := m.runPluginsInParallel(target, &opts, &wg)
			if err != nil {
				logrus.Errorf("failed to run plugins in parallel: %v", err)
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
func (m *Manager) runAll(target *models.TargetInfo, opts *models.Options) (*models.DTO, error) {
	var wg sync.WaitGroup
	var mu sync.Mutex

	partials := make([]*models.DTO, len(m.plugins))

	for i, p := range m.plugins {
		wg.Add(1)
		go func(idx int, p Plugin) {
			defer wg.Done()

			dto, err := p.Run(target, opts)
			if err != nil {
				logrus.Errorf("failed to run plugin %s: %v", p.Name(), err)
				return
			}
			logrus.Println("Plugin result: ", dto)

			mu.Lock()
			partials[idx] = dto
			mu.Unlock()
		}(i, p)
	}

	wg.Wait()

	if len(partials) == 0 {
		return nil, errors.New("no plugins ran successfully")
	}

	ret := models.DTO{Target: target.Domain}
	for _, pr := range partials {
		if pr != nil {
			logrus.Println("Partial result: ", pr)
			ret.Ports = append(ret.Ports, pr.Ports...)
			ret.DNS = append(ret.DNS, pr.DNS...)
			ret.Subdomains = append(ret.Subdomains, pr.Subdomains...)
			ret.Vulnerabilities = append(ret.Vulnerabilities, pr.Vulnerabilities...)
		}
	}

	return &ret, nil
}

// Settings sets up a plugin with new settings.
func (m *Manager) Settings(settings models.SettingsAPI) error {
	// Add or remove plugins based on new settings
	names, dbSettings := m.addOrRemovePlugins(settings)

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
			p.Configure(settings.Config)
			err := p.PrepareSyn()
			if err != nil {
				logrus.Fatalf("failed to prepare SYN scan: %v", err)
			}
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

// addOrRemovePlugins adds or removes plugins based on the settings.
func (m *Manager) addOrRemovePlugins(settings models.SettingsAPI) (names []string, dbSettings database.SettingsDB) {
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

	return
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
