package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

var newCookieSettings = map[string]string{
	"AUTENTICO_CSRF_COOKIE_NAME":                 "_gorilla_csrf",
	"AUTENTICO_TRUSTED_DEVICE_COOKIE_NAME":       "autentico_trusted_device",
	"AUTENTICO_FEDERATION_COOKIE_NAME":           "autentico_federation",
	"AUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME": "autentico_passkey_registration",
	"AUTENTICO_FORWARD_AUTH_COOKIE_PREFIX":       "autentico_fa_",
}

func cookieTestConfig(t *testing.T) {
	t.Helper()
	saved := Bootstrap
	t.Cleanup(func() { Bootstrap = saved })
	for env := range newCookieSettings {
		t.Setenv(env, "")
		require.NoError(t, os.Unsetenv(env))
	}
}

func TestCookieNamesDefaultAndEnvironmentOverrides(t *testing.T) {
	cookieTestConfig(t)
	require.NoError(t, InitBootstrap())
	require.Equal(t, "_gorilla_csrf", Bootstrap.AuthCSRFCookieName)
	require.Equal(t, "autentico_trusted_device", Bootstrap.AuthTrustedDeviceCookieName)
	require.Equal(t, "autentico_federation", Bootstrap.AuthFederationCookieName)
	require.Equal(t, "autentico_passkey_registration", Bootstrap.AuthPasskeyRegistrationCookieName)
	require.Equal(t, "autentico_fa_", Bootstrap.AuthForwardAuthCookiePrefix)
	for env := range newCookieSettings {
		t.Setenv(env, "tenant_"+strings.TrimPrefix(env, "AUTENTICO_"))
	}
	require.NoError(t, InitBootstrap())
	require.Equal(t, "tenant_CSRF_COOKIE_NAME", Bootstrap.AuthCSRFCookieName)
	require.Equal(t, "tenant_TRUSTED_DEVICE_COOKIE_NAME", Bootstrap.AuthTrustedDeviceCookieName)
	require.Equal(t, "tenant_FEDERATION_COOKIE_NAME", Bootstrap.AuthFederationCookieName)
	require.Equal(t, "tenant_PASSKEY_REGISTRATION_COOKIE_NAME", Bootstrap.AuthPasskeyRegistrationCookieName)
	require.Equal(t, "tenant_FORWARD_AUTH_COOKIE_PREFIX", Bootstrap.AuthForwardAuthCookiePrefix)
}

func TestCookieNamesFromExplicitEnvFile(t *testing.T) {
	cookieTestConfig(t)
	// godotenv loads into the environment; reserve every key for cleanup while
	// removing it so file values can actually take effect.
	for env := range newCookieSettings {
		require.NoError(t, os.Unsetenv(env))
	}
	file := filepath.Join(t.TempDir(), "cookies.env")
	require.NoError(t, os.WriteFile(file, []byte("AUTENTICO_CSRF_COOKIE_NAME=file_csrf\nAUTENTICO_TRUSTED_DEVICE_COOKIE_NAME=file_trusted\nAUTENTICO_FEDERATION_COOKIE_NAME=file_federation\nAUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME=file_passkey\nAUTENTICO_FORWARD_AUTH_COOKIE_PREFIX=file_fa_\n"), 0600))
	t.Setenv("AUTENTICO_CSRF_COOKIE_NAME", "process_csrf")
	require.NoError(t, InitBootstrap(file))
	require.Equal(t, "process_csrf", Bootstrap.AuthCSRFCookieName)
	require.Equal(t, "file_trusted", Bootstrap.AuthTrustedDeviceCookieName)
	require.Equal(t, "file_federation", Bootstrap.AuthFederationCookieName)
	require.Equal(t, "file_passkey", Bootstrap.AuthPasskeyRegistrationCookieName)
	require.Equal(t, "file_fa_", Bootstrap.AuthForwardAuthCookiePrefix)
}

func TestExistingCookieSettingsRemainLiteral(t *testing.T) {
	cookieTestConfig(t)
	t.Setenv("AUTENTICO_IDP_SESSION_COOKIE_NAME", "__Host-tenant_idp")
	t.Setenv("AUTENTICO_REFRESH_TOKEN_COOKIE_NAME", "tenant_refresh")
	require.NoError(t, InitBootstrap())
	require.Equal(t, "__Host-tenant_idp", Bootstrap.AuthIdpSessionCookieName)
	require.Equal(t, "tenant_refresh", Bootstrap.AuthRefreshTokenCookieName)
}

func TestInvalidCookieNamesDoNotReplaceBootstrap(t *testing.T) {
	for env := range newCookieSettings {
		for _, value := range []string{"", "bad name", "bad;name", "bad=name", "bad\r\nname", "bäd", strings.Repeat("x", 129), "__Host-tenant", "__Secure-tenant", "__Http-tenant", "__hOsT-tenant"} {
			t.Run(env+"/"+value, func(t *testing.T) {
				cookieTestConfig(t)
				previous := Bootstrap
				t.Setenv(env, value)
				err := InitBootstrap()
				require.ErrorContains(t, err, env)
				require.Equal(t, previous, Bootstrap)
			})
		}
	}
}

func TestCookieNamespaceCollisionsFailStartup(t *testing.T) {
	for _, settings := range []map[string]string{
		{"AUTENTICO_CSRF_COOKIE_NAME": "autentico_idp_session"},
		{"AUTENTICO_TRUSTED_DEVICE_COOKIE_NAME": "_gorilla_csrf"},
		{"AUTENTICO_FEDERATION_COOKIE_NAME": "binding", "AUTENTICO_PASSKEY_REGISTRATION_COOKIE_NAME": "binding"},
		{"AUTENTICO_FORWARD_AUTH_COOKIE_PREFIX": "autentico_"},
	} {
		t.Run("collision", func(t *testing.T) {
			cookieTestConfig(t)
			for env, value := range settings {
				t.Setenv(env, value)
			}
			previous := Bootstrap
			require.Error(t, InitBootstrap())
			require.Equal(t, previous, Bootstrap)
		})
	}
}
