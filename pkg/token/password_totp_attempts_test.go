package token

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/mfa"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPasswordGrantRejectsSuccessfulTotpReplay(t *testing.T) {
	testutils.WithTestDB(t)
	usr, err := user.CreateUser("grant-replay", "password123", "grant-replay@example.com")
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	insertROPCTestClient(t)
	code, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	for i := range 2 {
		form := url.Values{
			"grant_type": {"password"}, "client_id": {"ropc-test-client"},
			"username": {"grant-replay"}, "password": {"password123"}, "totp_code": {code},
		}
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		HandleToken(rr, req)
		if i == 0 {
			require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
		} else {
			require.Equal(t, http.StatusForbidden, rr.Code, rr.Body.String())
			require.Contains(t, rr.Body.String(), "invalid_mfa_code")
		}
	}
	var issued int
	require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens WHERE user_id=?", usr.ID).Scan(&issued))
	require.Equal(t, 1, issued)
}

// TestPasswordGrantTotpBudgetAcrossIPs verifies repeated correct passwords cannot bypass MFA lockout.
func TestPasswordGrantTotpBudgetAcrossIPs(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Bootstrap.AuthRefreshTokenCookieOnly = false
		config.Values.AuthAccountLockoutDuration = 2 * time.Minute
		config.Values.AuditLogRetentionStr = "30d"
	})
	usr, err := user.CreateUser("grant-budget", "password123", "grant-budget@example.com")
	require.NoError(t, err)
	const secret = "JBSWY3DPEHPK3PXP"
	require.NoError(t, user.SaveTotpSecret(usr.ID, secret))
	insertROPCTestClient(t)
	var invalid string
	for candidate := 0; candidate < 1000000; candidate++ {
		invalid = fmt.Sprintf("%06d", candidate)
		if !mfa.ValidateTotpCode(secret, invalid) {
			break
		}
	}
	send := func(code, ip string) *httptest.ResponseRecorder {
		form := url.Values{
			"grant_type": {"password"}, "client_id": {"ropc-test-client"},
			"username": {"grant-budget"}, "password": {"password123"}, "totp_code": {code},
		}
		req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = ip + ":12345"
		rr := httptest.NewRecorder()
		HandleToken(rr, req)
		return rr
	}
	for i := range 5 {
		rr := send(invalid, fmt.Sprintf("198.51.100.%d", i+1))
		require.Equal(t, http.StatusForbidden, rr.Code)
		if i < 4 {
			assert.Contains(t, rr.Body.String(), "invalid_mfa_code")
		} else {
			assert.Contains(t, rr.Body.String(), "mfa_locked")
		}
	}
	valid, err := totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	rr := send(valid, "203.0.113.1")
	require.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "mfa_locked")
	var passwordFailures, totpFailures int
	require.NoError(t, db.GetDB().QueryRow(`SELECT failed_login_attempts, totp_failed_attempts FROM users WHERE id = ?`, usr.ID).Scan(&passwordFailures, &totpFailures))
	assert.Zero(t, passwordFailures)
	assert.Equal(t, 5, totpFailures)
	var tokens int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM tokens WHERE user_id = ?`, usr.ID).Scan(&tokens))
	assert.Zero(t, tokens)
	var audits int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs
		WHERE event = 'mfa_failed' AND target_id = ? AND json_extract(detail, '$.reason') = 'account_attempts_exhausted'`, usr.ID).Scan(&audits))
	assert.Positive(t, audits)

	_, err = db.GetDB().Exec(`UPDATE users SET totp_locked_until = ? WHERE id = ?`, time.Now().Add(-time.Second), usr.ID)
	require.NoError(t, err)
	valid, err = totp.GenerateCode(secret, time.Now())
	require.NoError(t, err)
	rr = send(valid, "203.0.113.2")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	assert.Contains(t, rr.Body.String(), "access_token")
}
