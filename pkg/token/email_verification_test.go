package token

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

func TestPasswordGrantRequiresEmailVerification(t *testing.T) {
	for _, tc := range []struct {
		name                               string
		required, verified, admin, noEmail bool
		status                             int
	}{
		{name: "required unverified", required: true, status: 400},
		{name: "required verified", required: true, verified: true, status: 200},
		{name: "optional unverified", status: 200},
		{name: "optional verified", verified: true, status: 200},
		{name: "admin recovery exemption", required: true, admin: true, status: 200},
		{name: "missing email", required: true, noEmail: true, status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.RequireEmailVerification = tc.required; config.Values.RequireMfa = false })
			insertROPCTestClient(t)
			address := "verification@example.com"
			if tc.noEmail {
				address = ""
			}
			created, err := user.CreateUser("email-gate-user", "password123", address)
			require.NoError(t, err)
			role := "user"
			if tc.admin {
				role = "admin"
			}
			_, err = db.GetDB().Exec("UPDATE users SET is_email_verified=?,role=? WHERE id=?", tc.verified, role, created.ID)
			require.NoError(t, err)
			req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{"grant_type": {"password"}, "client_id": {"ropc-test-client"}, "username": {"email-gate-user"}, "password": {"password123"}, "scope": {"openid"}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleToken(rr, req)
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			var tokens, sessions int
			require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM tokens").Scan(&tokens))
			require.NoError(t, db.GetDB().QueryRow("SELECT count(*) FROM sessions").Scan(&sessions))
			if tc.status == 400 {
				require.Contains(t, rr.Body.String(), "invalid_grant")
				require.NotContains(t, rr.Body.String(), "access_token")
				require.Zero(t, tokens)
				require.Zero(t, sessions)
			} else {
				require.Equal(t, 1, tokens)
				require.Equal(t, 1, sessions)
			}
		})
	}
}

func TestPasswordGrantEmailVerificationPrecedesMFA(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		enrolled, admin, validCode bool
		code                       string
		status                     int
		errorCode                  string
	}{
		{name: "unverified unenrolled", status: 400, errorCode: "invalid_grant"},
		{name: "unverified enrolled invalid OTP", enrolled: true, code: "invalid", status: 400, errorCode: "invalid_grant"},
		{name: "unverified enrolled valid OTP", enrolled: true, validCode: true, status: 400, errorCode: "invalid_grant"},
		{name: "admin still needs enrollment", admin: true, status: 403, errorCode: "mfa_required"},
		{name: "admin still needs OTP", admin: true, enrolled: true, status: 403, errorCode: "mfa_required"},
		{name: "admin with OTP", admin: true, enrolled: true, validCode: true, status: 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.RequireEmailVerification = true; config.Values.RequireMfa = true })
			insertROPCTestClient(t)
			usr, err := user.CreateUser("email-mfa-user", "password123", "unverified@example.com")
			require.NoError(t, err)
			role := "user"
			if tc.admin {
				role = "admin"
			}
			_, err = db.GetDB().Exec(`UPDATE users SET role=?,is_email_verified=FALSE WHERE id=?`, role, usr.ID)
			require.NoError(t, err)
			const seed = "JBSWY3DPEHPK3PXP"
			if tc.enrolled {
				require.NoError(t, user.SaveTotpSecret(usr.ID, seed))
			}
			_, err = db.GetDB().Exec(`UPDATE users SET totp_last_used_step=42,totp_failed_attempts=2 WHERE id=?`, usr.ID)
			require.NoError(t, err)
			code := tc.code
			if tc.validCode {
				code, err = totp.GenerateCode(seed, time.Now())
				require.NoError(t, err)
			}
			req := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(url.Values{"grant_type": {"password"}, "client_id": {"ropc-test-client"}, "username": {"email-mfa-user"}, "password": {"password123"}, "scope": {"openid"}, "totp_code": {code}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rr := httptest.NewRecorder()
			HandleToken(rr, req)
			require.Equal(t, tc.status, rr.Code)
			if tc.status != 200 {
				require.Contains(t, rr.Body.String(), tc.errorCode)
				if !tc.admin {
					require.Contains(t, rr.Body.String(), "Email verification is required")
				}
				var step int64
				var attempts, tokens, sessions int
				require.NoError(t, db.GetDB().QueryRow(`SELECT totp_last_used_step,totp_failed_attempts FROM users WHERE id=?`, usr.ID).Scan(&step, &attempts))
				require.EqualValues(t, 42, step)
				require.Equal(t, 2, attempts)
				require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM tokens`).Scan(&tokens))
				require.Zero(t, tokens)
				require.NoError(t, db.GetDB().QueryRow(`SELECT count(*) FROM sessions`).Scan(&sessions))
				require.Zero(t, sessions)
			} else {
				require.Contains(t, rr.Body.String(), "access_token")
			}
		})
	}
}
