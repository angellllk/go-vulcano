package core

import (
	"errors"
	"net/url"
)

// TargetInfo holds information about a target.
type TargetInfo struct {
	FullURL string
	Domain  string
}

// ParseTargetInfo parses a URL string into a TargetInfo structure.
func ParseTargetInfo(rawURL string) (TargetInfo, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return TargetInfo{}, err
	}

	domain := u.Hostname()
	if len(domain) == 0 {
		return TargetInfo{}, errors.New("invalid domain")
	}

	return TargetInfo{
		FullURL: rawURL,
		Domain:  domain,
	}, nil
}
