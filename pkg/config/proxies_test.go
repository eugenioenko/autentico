package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrustedProxyBootstrap(t *testing.T) {
	saved := Bootstrap
	t.Cleanup(func() { Bootstrap = saved })
	t.Setenv("AUTENTICO_TRUSTED_PROXIES", " 127.0.0.1/32, 2001:db8::1/64,::ffff:10.1.1.1/120 ")
	require.NoError(t, InitBootstrap())
	require.Len(t, Bootstrap.TrustedProxies, 3)
	require.Equal(t, "127.0.0.1/32", Bootstrap.TrustedProxies[0].String())
	require.Equal(t, "2001:db8::/64", Bootstrap.TrustedProxies[1].String())
	require.Equal(t, "10.1.1.0/24", Bootstrap.TrustedProxies[2].String())
	t.Setenv("AUTENTICO_TRUSTED_PROXIES", "")
	require.NoError(t, InitBootstrap())
	require.Empty(t, Bootstrap.TrustedProxies)
	for _, raw := range []string{"localhost", "127.0.0.1", "127.0.0.1/33", "::1/129", "fe80::1%eth0/64", "127.0.0.1/32,", ",", "127.0.0.1/32,bad"} {
		t.Setenv("AUTENTICO_TRUSTED_PROXIES", raw)
		require.ErrorContains(t, InitBootstrap(), "AUTENTICO_TRUSTED_PROXIES", raw)
		require.Empty(t, Bootstrap.TrustedProxies, "failed loading must not partially replace configuration")
	}
}
