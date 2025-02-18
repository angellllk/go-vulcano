package core

import (
	"sync"
)

type PluginManager struct {
	plugins []Plugin
}

func NewPluginManager() *PluginManager {
	return &PluginManager{
		plugins: make([]Plugin, 0),
	}
}

func (pm *PluginManager) AddPlugin(p Plugin) error {
	pm.plugins = append(pm.plugins, p)
	return nil
}

func (pm *PluginManager) GetPluginByName(name string) Plugin {
	for _, p := range pm.plugins {
		if p.Name() == name {
			return p
		}
	}
	return nil
}

func (pm *PluginManager) RemovePlugin(name string) bool {
	var ok bool
	for i, p := range pm.plugins {
		if p.Name() == name {
			pm.plugins = append(pm.plugins[:i], pm.plugins[i+1:]...)
			ok = true
		}
	}
	return ok
}

func (pm *PluginManager) Count() int {
	return len(pm.plugins)
}

func (pm *PluginManager) RunAll(target *TargetInfo) (*ScanResult, error) {
	partials := make([]ScanResult, len(pm.plugins))
	var wg sync.WaitGroup
	errors := make([]error, len(pm.plugins))

	for i, plugin := range pm.plugins {
		wg.Add(1)
		go func(idx int, p Plugin) {
			defer wg.Done()

			pr, err := p.Run(target)
			if err != nil {
				errors[idx] = err
				return
			}
			partials[idx] = pr
		}(i, plugin)
	}

	wg.Wait()

	var result ScanResult
	for _, pr := range partials {
		result.DNS = append(result.DNS, pr.DNS...)
		result.Subdomains = append(result.Subdomains, pr.Subdomains...)
		result.Ports = append(result.Ports, pr.Ports...)
		result.Vulnerabilities = append(result.Vulnerabilities, pr.Vulnerabilities...)
	}

	return &result, nil
}
