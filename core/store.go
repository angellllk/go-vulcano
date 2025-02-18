package core

import (
	"net/url"
	"strings"
	"sync"
)

var testedParams = make(map[string]bool)
var mu sync.Mutex

func NormalizeURL(target string) string {
	parsedURL, err := url.Parse(target)
	if err != nil {
		return target
	}

	pathParts := strings.Split(parsedURL.Path, "/")
	if len(pathParts) > 2 {
		parsedURL.Path = strings.Join(pathParts[:2], "/")
	}

	return parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
}

func IsAlreadyTested(url, param string) bool {
	mu.Lock()
	defer mu.Unlock()

	key := NormalizeURL(url) + "|" + param
	return testedParams[key]
}

func MarkAsTested(url, param string) {
	mu.Lock()
	defer mu.Unlock()

	key := NormalizeURL(url) + "|" + param
	testedParams[key] = true
}
