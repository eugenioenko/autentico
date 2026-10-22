package federation

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// isPrivateIP rejects local, private and shared address space, including mapped IPv4.
func isPrivateIP(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}
	// RFC 6598 shared space includes cloud metadata endpoints; 0/8 and
	// reserved class E addresses are not external provider destinations.
	v4 := ip.To4()
	return v4 != nil && (v4[0] == 0 || v4[0] >= 224 || (v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127))
}

// checkFederationAddress validates the actual resolved socket target before connecting.
func checkFederationAddress(_ string, address string, _ syscall.RawConn) error {
	// OWASP SSRF Prevention §IP address / §Domain name: check the IP used by
	// the connection, avoiding a separate DNS check followed by a second lookup.
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid federation destination: %w", err)
	}
	if isPrivateIP(net.ParseIP(host)) {
		return fmt.Errorf("federation connection to private IP address blocked: %s", host)
	}
	return nil
}

// federationDialer checks each resolved address, including retries and IPv6 fallback.
func federationDialer() *net.Dialer {
	return &net.Dialer{Timeout: 5 * time.Second, Control: checkFederationAddress}
}

// safeHTTPClient protects discovery, token and JWKS requests and their redirects.
func safeHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
		// The transport does not use environment proxies: every outbound HTTP
		// connection must pass the resolved-address check in this dialer.
		Transport: &http.Transport{DialContext: federationDialer().DialContext},
	}
}
