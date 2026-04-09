package federation

import (
	"fmt"
	"net"
	"net/http"
	"time"
)

// isPrivateIP checks if an IP address belongs to a private, loopback, or link-local range.
func isPrivateIP(ip net.IP) bool {
	privateRanges := []string{
		"127.0.0.0/8",    // Loopback
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918
		"169.254.0.0/16", // Link-local
		"::1/128",        // IPv6 loopback
		"fc00::/7",       // IPv6 unique local
		"fe80::/10",      // IPv6 link-local
	}
	for _, cidr := range privateRanges {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// safeHTTPClient returns an HTTP client that blocks redirects to private/loopback
// addresses and limits the number of redirects. Used for OIDC discovery and token
// exchange with external federation providers to prevent SSRF.
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		// Block redirects to private IP ranges.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			host := req.URL.Hostname()
			ips, err := net.LookupHost(host)
			if err != nil {
				return fmt.Errorf("failed to resolve redirect target %q: %w", host, err)
			}
			for _, ipStr := range ips {
				ip := net.ParseIP(ipStr)
				if ip != nil && isPrivateIP(ip) {
					return fmt.Errorf("redirect to private IP address blocked: %s", ipStr)
				}
			}
			return nil
		},
		// Also check the initial dial target to prevent direct requests to private IPs.
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 5 * time.Second,
			}).DialContext,
		},
	}
}
