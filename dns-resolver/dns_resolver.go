package dns_resolver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type DNSResolver struct{}

// DNSResolverConfig defines the configuration parameters used to be used
// by the end-user to redefine settings.
type DNSResolverConfig struct{}

// Name returns plugin's name.
func (d *DNSResolver) Name() string {
	return "DNS Resolver"
}

// fetchCRTSubdomains queries over crt.sh to fetch associated subdomains.
func fetchCRTSubdomains(domain string) ([]string, error) {
	// "%25" is encoded for "%"
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	client := &http.Client{Timeout: 15 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}

	subdomainSet := make(map[string]struct{})
	for _, entry := range entries {
		// Some certificates can contain domains separated by new line.
		domains := strings.Split(entry.NameValue, "\n")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			// Exclude wildcards
			d = strings.TrimPrefix(d, "*.")
			if d != "" {
				subdomainSet[d] = struct{}{}
			}
		}
	}

	var subdomains []string
	for s := range subdomainSet {
		subdomains = append(subdomains, s)
	}
	return subdomains, nil
}

// lookupSubdomain runs the DNS lookup for every subdomain and sends the results to the channel.
func (d *DNSResolver) lookupSubdomain(ctx context.Context, target *models.TargetInfo, sd string, resultsCh chan<- lookupResult) {
	fullSubdomain := sd
	if !strings.Contains(sd, ".") {
		fullSubdomain = fmt.Sprintf("%s.%s", sd, target.Domain)
	}
	ips, err := net.DefaultResolver.LookupHost(ctx, fullSubdomain)
	if err != nil {
		logrus.Debugf("Lookup failed for %s: %v", fullSubdomain, err)
		return
	}
	logrus.Infof("Resolved %s -> %v", fullSubdomain, ips)
	resultsCh <- lookupResult{
		subdomain: fullSubdomain,
		ips:       ips,
	}
}

// startLocalLookups launches goroutines for each subdomain from the local list.
func (d *DNSResolver) startLocalLookups(ctx context.Context, target *models.TargetInfo, resultsCh chan<- lookupResult, wg *sync.WaitGroup) {
	for _, sub := range commonSubdomains {
		wg.Add(1)
		go func(s string) {
			defer wg.Done()
			d.lookupSubdomain(ctx, target, s, resultsCh)
		}(sub)
	}
}

// startCRTSubdomainLookups obtains subdomains from crt.sh and launches goroutines for each one of them.
func (d *DNSResolver) startCRTSubdomainLookups(ctx context.Context, target *models.TargetInfo, resultsCh chan<- lookupResult, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		subdomains, err := fetchCRTSubdomains(target.Domain)
		if err != nil {
			logrus.Errorf("Error fetching crt.sh data: %v", err)
			return
		}
		for _, sd := range subdomains {
			wg.Add(1)
			go func(s string) {
				defer wg.Done()
				d.lookupSubdomain(ctx, target, s, resultsCh)
			}(sd)
		}
	}()
}

// normalizeSubdomain removes "www." from a subdomain.
func normalizeSubdomain(sd string) string {
	return strings.TrimPrefix(sd, "www.")
}

// contains verifies if a value exists within a slice.
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// aggregateResults receives the results from the channel and aggregates them.
func (d *DNSResolver) aggregateResults(resultsCh <-chan lookupResult) models.DTO {
	var result models.DTO
	ipSet := make(map[string]struct{})
	subdomainMap := make(map[string]models.SubdomainDTO)

	for res := range resultsCh {
		norm := normalizeSubdomain(res.subdomain)
		if existing, exists := subdomainMap[norm]; exists {
			for _, ip := range res.ips {
				if !contains(existing.IPs, ip) {
					existing.IPs = append(existing.IPs, ip)
				}
			}
			subdomainMap[norm] = existing
		} else {
			subdomainMap[norm] = models.SubdomainDTO{
				Name: norm,
				IPs:  res.ips,
			}
		}

		for _, ip := range res.ips {
			if _, exists := ipSet[ip]; !exists {
				ipSet[ip] = struct{}{}
				result.DNS = append(result.DNS, ip)
			}
		}
	}

	for _, dto := range subdomainMap {
		result.Subdomains = append(result.Subdomains, dto)
	}
	return result
}

// Run orchestrates the DNS resolving process.
func (d *DNSResolver) Run(target *models.TargetInfo, opts *models.Options) (*models.DTO, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	resultsCh := make(chan lookupResult, len(commonSubdomains))
	var wg sync.WaitGroup

	if target.Domain == "" {
		return nil, errors.New("no web domain set for target, skipping DNS reverse lookup")
	}

	d.startLocalLookups(ctx, target, resultsCh, &wg)
	d.startCRTSubdomainLookups(ctx, target, resultsCh, &wg)

	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	dto := d.aggregateResults(resultsCh)
	return &dto, nil
}
