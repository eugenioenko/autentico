package utils

import (
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestGetClientIP(t *testing.T) {
	for _, tc := range []struct {
		name, peer, proxies string
		forwarded           []string
		want                string
	}{
		{"direct", "192.0.2.10:5000", "", nil, "192.0.2.10"},
		{"ignore forged header by default", "192.0.2.10:5000", "", []string{"203.0.113.2"}, "192.0.2.10"},
		{"untrusted peer", "192.0.2.10:5000", "127.0.0.1/32", []string{"203.0.113.2"}, "192.0.2.10"},
		{"trusted local proxy", "127.0.0.1:5000", "127.0.0.1/32", []string{"192.0.2.10"}, "192.0.2.10"},
		{"nginx appended real client", "127.0.0.1:5000", "127.0.0.1/32", []string{"203.0.113.99, 192.0.2.10"}, "192.0.2.10"},
		{"ignore malformed attacker prefix", "127.0.0.1:5000", "127.0.0.1/32", []string{"garbage,, 192.0.2.10"}, "192.0.2.10"},
		{"multiple proxies", "127.0.0.1:5000", "127.0.0.1/32,10.1.0.0/16", []string{"203.0.113.99, 192.0.2.10, 10.1.1.2"}, "192.0.2.10"},
		{"stop at untrusted intermediate", "127.0.0.1:5000", "127.0.0.1/32", []string{"192.0.2.10, 10.1.1.2"}, "10.1.1.2"},
		{"multiple header fields", "127.0.0.1:5000", "127.0.0.1/32,10.1.0.0/16", []string{"203.0.113.99, 192.0.2.10", "10.1.1.2"}, "192.0.2.10"},
		{"IPv6 peer", "[2001:db8::2]:5000", "2001:db8::/64", []string{"2001:db8:1::10"}, "2001:db8:1::10"},
		{"mapped peer and client", "[::ffff:127.0.0.1]:5000", "127.0.0.1/32", []string{"::ffff:192.0.2.10"}, "192.0.2.10"},
		{"bare IPv4 peer", "192.0.2.10", "", nil, "192.0.2.10"},
		{"bare IPv6 peer", "2001:db8::2", "", nil, "2001:db8::2"},
		{"missing header", "127.0.0.1:5000", "127.0.0.1/32", nil, "127.0.0.1"},
		{"empty header", "127.0.0.1:5000", "127.0.0.1/32", []string{""}, "127.0.0.1"},
		{"malformed nearest hop", "127.0.0.1:5000", "127.0.0.1/32", []string{"192.0.2.10, nope"}, "127.0.0.1"},
		{"empty nearest hop", "127.0.0.1:5000", "127.0.0.1/32", []string{"192.0.2.10,"}, "127.0.0.1"},
		{"scoped forwarded address", "127.0.0.1:5000", "127.0.0.1/32", []string{"fe80::1%eth0"}, "127.0.0.1"},
		{"forwarded address with port", "127.0.0.1:5000", "127.0.0.1/32", []string{"192.0.2.10:1234"}, "127.0.0.1"},
		{"all hops trusted", "127.0.0.1:5000", "127.0.0.1/32,10.1.0.0/16", []string{"10.1.1.2"}, "127.0.0.1"},
		{"unparseable peer cannot trust headers", "unknown", "127.0.0.1/32", []string{"192.0.2.10"}, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saved := config.Bootstrap
			t.Cleanup(func() { config.Bootstrap = saved })
			config.Bootstrap.TrustedProxies = nil
			for _, value := range strings.Split(tc.proxies, ",") {
				if value != "" {
					config.Bootstrap.TrustedProxies = append(config.Bootstrap.TrustedProxies, netip.MustParsePrefix(value))
				}
			}
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.peer
			for _, value := range tc.forwarded {
				r.Header.Add("X-Forwarded-For", value)
			}
			r.Header.Set("X-Real-IP", "203.0.113.77")
			r.Header.Set("Forwarded", "for=203.0.113.88")
			require.Equal(t, tc.want, GetClientIP(r))
		})
	}
}
