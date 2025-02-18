package core

import (
	"context"
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"time"
)

type Subdomain struct {
	Name string   `json:"name"`
	IPs  []string `json:"ips"`
}

type DNSResolver struct {
}

// DNSResolverConfig defines the configuration parameters used to be used
// by the end-user to redefine settings.
type DNSResolverConfig struct{}

func (d *DNSResolver) Name() string {
	return "DNS Resolver"
}

func (d *DNSResolver) Run(target *TargetInfo) (ScanResult, error) {
	var result ScanResult

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, sub := range commonSubdomains {
		// Check if context is done.
		select {
		case <-ctx.Done():
			return ScanResult{}, ctx.Err()
		default:
		}
		fullSubdomain := fmt.Sprintf("%s.%s", sub, target.Domain)
		ips, err := net.LookupHost(fullSubdomain)
		if err == nil {
			logrus.Infof("🌍 DNS Resolved: %s -> %v", fullSubdomain, ips)
		} else {
			logrus.Debugf("DNS lookup failed for %s: %v", fullSubdomain, err)
			continue
		}

		for _, ip := range ips {
			found := false
			for _, existing := range result.DNS {
				if ip == existing {
					found = true
					break
				}
			}
			if !found {
				result.DNS = append(result.DNS, ip)
			}
		}

		result.Subdomains = append(result.Subdomains, Subdomain{
			Name: fullSubdomain,
			IPs:  ips,
		})
	}

	return result, nil
}
