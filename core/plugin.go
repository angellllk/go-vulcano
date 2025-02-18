package core

const (
	portScanner = "Port Scanner"
	dnsResolver = "DNS Resolver"
)

type Plugin interface {
	Name() string
	Run(target *TargetInfo) (ScanResult, error)
}
