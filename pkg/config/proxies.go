package config

import (
	"fmt"
	"net/netip"
	"strings"
)

func parseTrustedProxies(raw string) ([]netip.Prefix, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var proxies []netip.Prefix
	for _, value := range strings.Split(raw, ",") {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("invalid AUTENTICO_TRUSTED_PROXIES entry %q: expected an IPv4 or IPv6 CIDR: %w", value, err)
		}
		// Normalize IPv4-mapped IPv6 ranges just like client addresses.
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		proxies = append(proxies, prefix.Masked())
	}
	return proxies, nil
}
