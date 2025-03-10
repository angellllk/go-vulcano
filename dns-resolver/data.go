package dns_resolver

// Structure used for transporting results after each search
type lookupResult struct {
	subdomain string
	ips       []string
}

var commonSubdomains = []string{
	"www",
	"mail",
	"ftp",
	"api",
	"blog",
	"webmail",
	"ns1",
	"ns2",
	"smtp",
	"pop",
	"imap",
	"m",
	"mobile",
	"admin",
	"dev",
	"test",
	"staging",
	"vpn",
	"intranet",
	"portal",
	"shop",
	"store",
	"support",
	"docs",
	"download",
	"static",
	"images",
	"assets",
	"forum",
	"news",
	"beta",
	"secure",
	"backup",
	"cdn",
	"cache",
	"api2",
	"demo",
	"old",
	"erp",
	"crm",
	"wiki",
	"help",
	"pay",
	"checkout",
	"live",
	"web",
	"app",
	"apps",
	"preview",
	"dashboard",
	"reports",
	"console",
	"tracking",
	"stats",
	"video",
	"media",
	"panel",
}

// crtEntry defines the JSON structure returned by crt.sh
type crtEntry struct {
	NameValue string `json:"name_value"`
}
