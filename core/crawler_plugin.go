package core

import (
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

var VisitedLinks = make(map[string]bool)

// CrawlWebsiteContext recursively crawls pages until depth==0,
// using the provided context to allow cancellation.
func CrawlWebsiteContext(ctx context.Context, baseURL, currentURL string, depth int) {
	if depth == 0 {
		return
	}

	// Check for cancellation.
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Avoid revisiting URLs.
	if VisitedLinks[currentURL] {
		return
	}
	VisitedLinks[currentURL] = true

	req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
	if err != nil {
		logrus.Errorf("Error creating request for %s: %v", currentURL, err)
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		logrus.Errorf("error fetching", currentURL, ":", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		fmt.Println("error parsing document:", err)
		return
	}

	// Iterate over <a> elements.
	doc.Find("a").Each(func(index int, item *goquery.Selection) {
		link, exists := item.Attr("href")
		if !exists {
			return
		}
		// Filter out fragments and javascript links.
		if strings.HasPrefix(link, "#") || strings.HasPrefix(strings.ToLower(link), "javascript:") {
			return
		}
		// If the link is relative, construct the full URL.
		if strings.HasPrefix(link, "/") {
			link = baseURL + link
		}
		// Only follow HTTP/HTTPS links.
		if strings.HasPrefix(link, "http") {
			CrawlWebsiteContext(ctx, baseURL, link, depth-1)
		}
	})
}

// CrawlerPlugin implements the Plugin interface for website crawling.
type CrawlerPlugin struct {
	Depth int
}

func (c *CrawlerPlugin) Name() string {
	return "Website Crawler"
}

func (c *CrawlerPlugin) Run(target TargetInfo) error {
	// Create a context with a timeout for crawling.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logrus.Infof("Starting crawling on %s with depth %d", target.FullURL, c.Depth)
	CrawlWebsiteContext(ctx, target.FullURL, target.FullURL, c.Depth)
	return nil
}
