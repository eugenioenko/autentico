package security

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/emailverification"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func browserAuthorization(t *testing.T, ts *TestServer) url.Values {
	t.Helper()
	p := federationParams()
	p.Set("response_type", "code")
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/authorize?" + p.Encode())
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	p.Set("gorilla.csrf.Token", getCSRFToken(string(body)))
	p.Set("authorize_sig", getAuthorizeSig(string(body)))
	require.NotEmpty(t, p.Get("authorize_sig"))
	require.NotEmpty(t, p.Get("gorilla.csrf.Token"))
	return p
}

// A real SMTP delivery verifies that authorization fields survive the complete
// page -> resend -> email link -> verification -> PKCE exchange path.
func captureVerificationEmail(t *testing.T) <-chan string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	host, port, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	testutils.WithConfigOverride(t, func() {
		config.Values.MagicLinkEnabled = true
		config.Values.SmtpHost, config.Values.SmtpPort = host, port
		config.Values.SmtpUsername, config.Values.SmtpPassword = "", ""
		config.Values.SmtpFrom = "auth@example.com"
		config.Values.EmailVerificationExpiration = time.Hour
	})
	messages := make(chan string, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
		reader := textproto.NewReader(bufio.NewReader(conn))
		_, _ = fmt.Fprint(conn, "220 test SMTP\r\n")
		for {
			line, err := reader.ReadLine()
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"), strings.HasPrefix(line, "HELO"):
				_, _ = fmt.Fprint(conn, "250 test SMTP\r\n")
			case line == "DATA":
				_, _ = fmt.Fprint(conn, "354 send message\r\n")
				data, err := reader.ReadDotBytes()
				if err != nil {
					return
				}
				messages <- string(data)
				_, _ = fmt.Fprint(conn, "250 accepted\r\n")
			case line == "QUIT":
				_, _ = fmt.Fprint(conn, "221 bye\r\n")
				return
			default:
				_, _ = fmt.Fprint(conn, "250 OK\r\n")
			}
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); <-done })
	return messages
}

// RFC 6749 §4.1.1 / §10.6: no public page may sign an unvalidated redirect,
// client or scope that another handler could interpret as authorization.
func TestMagicLink_RefusesUnvalidatedSignature(t *testing.T) {
	ts := startTestServer(t)
	testutils.WithConfigOverride(t, func() { config.Values.MagicLinkEnabled = true; config.Values.SmtpHost = "smtp.example.com" })
	for _, tc := range []struct{ name, field, value string }{
		{"attacker redirect", "redirect_uri", "https://attacker.example/steal"},
		{"unknown client", "client_id", "unknown"},
		{"missing client", "client_id", ""},
		{"disallowed scope", "scope", "openid custom_claims"},
		{"missing PKCE", "code_challenge", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := federationParams()
			p.Set(tc.field, tc.value)
			resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/magic-link?" + p.Encode())
			require.NoError(t, err)
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			require.NoError(t, err)
			require.Equal(t, http.StatusBadRequest, resp.StatusCode)
			require.Empty(t, getAuthorizeSig(string(body)))
			require.Empty(t, resp.Header.Get("Location"))
		})
	}
}

// A signature from an older binary or from before a registration change must
// not turn an arbitrary callback into an authorized destination at any consumer.
func TestSignedAuthorization_RejectsInvalidConsumers(t *testing.T) {
	for _, tc := range []struct{ name, field, value, sql string }{
		{name: "attacker redirect", field: "redirect_uri", value: "https://attacker.example/steal"},
		{name: "unknown client", field: "client_id", value: "unknown"},
		{name: "disallowed scope", field: "scope", value: "openid custom_claims"},
		{name: "missing PKCE", field: "code_challenge"},
		{name: "disabled client", sql: "UPDATE clients SET is_active=FALSE WHERE client_id='test-client'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := startTestServer(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.AuthAllowSelfSignup = true
				config.Values.MagicLinkEnabled = true
				config.Values.SmtpHost = "smtp.example.com"
			})
			p := browserAuthorization(t, ts)
			if tc.field != "" {
				p.Set(tc.field, tc.value)
			}
			// Simulate a genuine historical signature, not an integrity failure.
			testutils.SetAuthorizeSig(p)
			if tc.sql != "" {
				_, err := db.GetDB().Exec(tc.sql)
				require.NoError(t, err)
			}
			victim := createTestUser(t, "victim", "password123", "victim@example.com")
			raw, hash, err := emailverification.GenerateToken()
			require.NoError(t, err)
			require.NoError(t, user.SetEmailVerificationToken(victim.ID, hash, time.Now().Add(time.Hour)))
			p.Set("token", raw)
			p.Set("username", "unauthorized-new-account")
			p.Set("email", "new@example.com")
			p.Set("password", "password123")
			p.Set("confirm_password", "password123")
			for _, path := range []string{"/oauth2/verify-email", "/oauth2/passkey/register/begin", "/oauth2/passkey/login/begin", "/oauth2/passkey/discoverable/begin"} {
				resp, err := ts.Client.Get(ts.BaseURL + path + "?" + p.Encode())
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusBadRequest, resp.StatusCode, path)
				require.Empty(t, resp.Header.Get("Location"), path)
			}
			for _, path := range []string{"/oauth2/signup", "/oauth2/magic-link", "/oauth2/resend-verification"} {
				if path == "/oauth2/resend-verification" {
					p.Set("username", "victim")
				}
				resp, err := ts.Client.PostForm(ts.BaseURL+path, p)
				require.NoError(t, err)
				_ = resp.Body.Close()
				require.Equal(t, http.StatusBadRequest, resp.StatusCode, path)
			}
			var verified bool
			var storedHash string
			require.NoError(t, db.GetDB().QueryRow("SELECT is_email_verified,email_verification_token FROM users WHERE id=?", victim.ID).Scan(&verified, &storedHash))
			require.False(t, verified)
			require.Equal(t, hash, storedHash, "invalid requests must not consume or rotate the verification token")
			for _, table := range []string{"auth_codes", "idp_sessions", "tokens", "sessions", "passkey_challenges", "magic_link_tokens"} {
				var count int
				require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM "+table).Scan(&count))
				require.Zero(t, count, table)
			}
			var count int
			require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM users").Scan(&count))
			require.Equal(t, 1, count)
		})
	}
}

func TestVerificationEmail_ValidatedMagicLinkSignatureRoundTrip(t *testing.T) {
	ts := startTestServer(t)
	messages := captureVerificationEmail(t)
	createTestUser(t, "email-victim", "password123", "email-victim@example.com")
	p := federationParams()
	p.Set("state", "state&code=attacker#fragment é")
	resp, err := ts.Client.Get(ts.BaseURL + "/oauth2/magic-link?" + p.Encode())
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	p.Set("authorize_sig", getAuthorizeSig(string(body)))
	p.Set("gorilla.csrf.Token", getCSRFToken(string(body)))
	require.NotEmpty(t, p.Get("authorize_sig"))
	p.Set("username", "email-victim")
	resp, err = ts.Client.PostForm(ts.BaseURL+"/oauth2/resend-verification", p)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var message string
	select {
	case message = <-messages:
	case <-time.After(2 * time.Second):
		t.Fatal("verification email was not delivered")
	}
	match := regexp.MustCompile(`href="([^"]*/verify-email\?[^"]*)"`).FindStringSubmatch(message)
	require.Len(t, match, 2, message)
	verificationURL := html.UnescapeString(match[1])
	resp, err = ts.Client.Get(verificationURL)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	callback, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "localhost:3000", callback.Host)
	require.Equal(t, p.Get("state"), callback.Query().Get("state"))
	require.Len(t, callback.Query()["code"], 1)
	tokens := exchangeCode(t, ts, callback.Query().Get("code"), p.Get("redirect_uri"), "test-client", testCodeVerifier)
	require.NotEmpty(t, tokens.AccessToken)
	// The resulting token belongs to the verified account, not the attacker.
	userinfo, err := http.NewRequest(http.MethodGet, ts.BaseURL+"/oauth2/userinfo", nil)
	require.NoError(t, err)
	userinfo.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	resp, err = ts.Client.Do(userinfo)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	var profile map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&profile))
	require.Equal(t, "email-victim@example.com", profile["email"])
}
