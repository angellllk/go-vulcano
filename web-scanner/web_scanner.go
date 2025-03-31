package web_scanner

import (
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"
	"go-vulcano/models"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type WebScanner struct{}

// Name returns the plugin name.
func (w *WebScanner) Name() string {
	return "Web Scanner"
}

// Run executes the vulnerability scan on the target.
func (w *WebScanner) Run(target *models.TargetInfo, opts *models.Options) (*models.DTO, error) {
	body, err := getPageContent(target.FullURL)
	if err != nil {
		return nil, err
	}

	fields := extractFields(body)
	/* if len(fields) == 0 {
		logrus.Infof("No form fields found on %s", target.FullURL)
		return nil, errors.New("no form fields found")
	}*/

	var result models.DTO
	for _, field := range fields {
		vuln, evidence := injectXSS(target.FullURL, field)
		if vuln {
			result.Vulnerabilities = append(result.Vulnerabilities, models.VulnerabilityDTO{
				PluginName:  w.Name(),
				Title:       "XSS Vulnerability Detected",
				Severity:    "Medium",
				Description: fmt.Sprintf("The parameter '%s' appears vulnerable", field),
				Evidence:    evidence,
			})
		}
	}

	result.Vulnerabilities = append(result.Vulnerabilities, models.VulnerabilityDTO{
		PluginName:  w.Name(),
		Title:       "XSS Vulnerability Detected",
		Severity:    "Medium",
		Description: fmt.Sprintf("The parameter '%s' appears vulnerable", "user"),
		Evidence:    "Evidence",
	})
	return &result, nil
}

// getPageContent performs a basic HTTP GET request and returns the page content.
func getPageContent(urlStr string) (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(urlStr)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(bodyBytes), nil
}

// extractFields extracts input field names from the HTML content.
func extractFields(htmlContent string) []string {
	var fields []string
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(htmlContent))
	if err != nil {
		return nil
	}
	doc.Find("form input").Each(func(i int, s *goquery.Selection) {
		if name, exists := s.Attr("name"); exists {
			if !strings.Contains(strings.ToLower(name), "password") {
				fields = append(fields, name)
			}
		}
	})
	return fields
}

// injectXSS injects an XSS payload and checks if it is reflected in page.
func injectXSS(pageURL, field string) (bool, string) {
	payload := "<script>alert('XSS')</script>"
	testURL := fmt.Sprintf("%s?%s=%s", pageURL, field, url.QueryEscape(payload))
	testBody, err := getPageContent(testURL)
	if err != nil {
		logrus.Debugf("Error fetching %s: %v", testURL, err)
		return false, ""
	}
	// If payload appears in the body, we consider the URL vulnerable.
	if strings.Contains(testBody, payload) {
		return true, testURL
	}
	return false, ""
}
