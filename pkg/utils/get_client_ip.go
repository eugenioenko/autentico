package utils

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
)

// GetClientIP trusts forwarded addresses only through explicitly configured
// proxy networks. Rate limiting, sessions and audit logs share this boundary.
func GetClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	peer = peer.WithZone("").Unmap()
	proxies := config.GetBootstrap().TrustedProxies
	// RFC 7239 §8.1: clients can forge forwarding headers. The network peer
	// must be trusted before any claimed address can affect the client identity.
	if !trustedProxy(peer, proxies) {
		return peer.String()
	}

	// RFC 7239 §7.1 / §8.1: preserve header-list order and walk from the
	// closest proxy back to the first untrusted hop. Ignore any prefix it supplied.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		hops := strings.Split(values[i], ",")
		for j := len(hops) - 1; j >= 0; j-- {
			ip, err := netip.ParseAddr(strings.TrimSpace(hops[j]))
			// Invalid or scoped forwarding claims cannot establish a client identity.
			if err != nil || ip.Zone() != "" {
				return peer.String()
			}
			ip = ip.Unmap()
			if !trustedProxy(ip, proxies) {
				return ip.String()
			}
		}
	}
	// Missing headers or a chain consisting entirely of trusted proxies does
	// not identify an untrusted client. Fall back to the actual network peer.
	return peer.String()
}

func trustedProxy(ip netip.Addr, proxies []netip.Prefix) bool {
	for _, proxy := range proxies {
		if proxy.Contains(ip) {
			return true
		}
	}
	return false
}
