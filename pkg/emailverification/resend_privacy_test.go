package emailverification

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func privacyResendRequest() *http.Request {
	form := url.Values{"username": {"resend-probe"}, "client_id": {"test-client"}, "redirect_uri": {"http://localhost/callback"}, "scope": {"openid"}}
	signVerificationParams(form)
	req := httptest.NewRequest(http.MethodPost, "/oauth2/resend-verification", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestResendVerificationHasOnePublicResponse(t *testing.T) {
	var generic string
	for _, state := range []string{"unknown", "unverified", "verified", "no email", "deactivated", "storage failure", "SMTP missing"} {
		t.Run(state, func(t *testing.T) {
			withVerificationTestDB(t)
			testutils.WithConfigOverride(t, func() {
				config.Values.SmtpHost = "smtp.example.test"
				config.Bootstrap.AntiTimingMinMs = 10
				config.Bootstrap.AntiTimingMaxMs = 11
			})
			if state == "SMTP missing" {
				config.Values.SmtpHost = ""
			}
			var id string
			if state != "unknown" {
				usr, err := user.CreateUser("resend-probe", "Password123!", "resend@example.com")
				require.NoError(t, err)
				id = usr.ID
				var query string
				switch state {
				case "verified":
					query = "UPDATE users SET is_email_verified=TRUE WHERE id=?"
				case "no email":
					query = "UPDATE users SET email='' WHERE id=?"
				case "deactivated":
					query = "UPDATE users SET deactivated_at=CURRENT_TIMESTAMP WHERE id=?"
				case "storage failure":
					query = "CREATE TRIGGER fail_resend BEFORE UPDATE OF email_verification_token ON users BEGIN SELECT RAISE(ABORT,'injected failure'); END"
				}
				if query != "" {
					var err error
					if state == "storage failure" {
						_, err = db.GetDB().Exec(query)
					} else {
						_, err = db.GetDB().Exec(query, id)
					}
					require.NoError(t, err)
				}
			}
			rr := httptest.NewRecorder()
			started := time.Now()
			sent := make(chan struct{})
			handleResendVerification(rr, privacyResendRequest(), func(string, string) error { close(sent); return nil }, make(chan struct{}, 1))
			require.GreaterOrEqual(t, time.Since(started), 10*time.Millisecond, "all account states must use the same delay policy")
			require.Equal(t, http.StatusOK, rr.Code)
			require.Empty(t, rr.Header().Get("Location"))
			require.NotContains(t, rr.Body.String(), "already verified")
			require.NotContains(t, rr.Body.String(), "Something went wrong")
			if state == "unknown" {
				generic = rr.Body.String()
			} else {
				require.Equal(t, generic, rr.Body.String())
			}
			if state == "unverified" {
				<-sent
				var hash string
				var expiry time.Time
				require.NoError(t, db.GetDB().QueryRow("SELECT email_verification_token,email_verification_expires_at FROM users WHERE id=?", id).Scan(&hash, &expiry))
				require.NotEmpty(t, hash)
				require.True(t, expiry.After(time.Now()))
			}
		})
	}
}

func TestResendReturnsWhileDeliveryIsBlockedAndLinkStillWorks(t *testing.T) {
	withVerificationTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.SmtpHost = "smtp.example.test"
		config.Bootstrap.AntiTimingMinMs = 0
		config.Bootstrap.AntiTimingMaxMs = 0
	})
	usr, err := user.CreateUser("resend-probe", "Password123!", "resend@example.com")
	require.NoError(t, err)
	type delivery struct{ to, link string }
	started := make(chan delivery, 1)
	release := make(chan struct{})
	senderDone := make(chan struct{})
	response := make(chan *httptest.ResponseRecorder, 1)
	handlerDone := make(chan struct{})
	inFlight := make(chan struct{}, 1)
	var unblock sync.Once
	cleanup := func() { unblock.Do(func() { close(release) }) }
	t.Cleanup(func() {
		cleanup()
		select {
		case <-handlerDone:
		case <-time.After(5 * time.Second):
			t.Error("handler did not stop")
		}
		// A returned handler with no admitted sender leaves the limiter empty;
		// otherwise wait until its delivery slot has been released as well.
		require.Eventually(t, func() bool { return len(inFlight) == 0 }, 5*time.Second, time.Millisecond)
	})
	go func() {
		defer close(handlerDone)
		rr := httptest.NewRecorder()
		handleResendVerification(rr, privacyResendRequest(), func(to, link string) error {
			defer close(senderDone)
			started <- delivery{to, link}
			<-release
			return nil
		}, inFlight)
		response <- rr
	}()
	var mail delivery
	select {
	case mail = <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("verification sender did not start")
	}

	select {
	case rr := <-response:
		require.Equal(t, http.StatusOK, rr.Code)
		require.Contains(t, rr.Body.String(), "Check your inbox")
		require.NotContains(t, rr.Body.String(), "already verified")
	case <-time.After(time.Second):
		t.Fatal("SMTP blocked the public response")
	}
	require.Equal(t, "resend@example.com", mail.to)
	parsed, err := url.Parse(mail.link)
	require.NoError(t, err)
	require.NotEmpty(t, parsed.Query().Get("token"))
	require.NotEmpty(t, parsed.Query().Get("authorize_sig"))
	cleanup()
	<-senderDone
	// A real signed verification link was stored before asynchronous delivery.
	rr := httptest.NewRecorder()
	HandleVerifyEmail(rr, httptest.NewRequest(http.MethodGet, mail.link, nil))
	require.Equal(t, http.StatusFound, rr.Code)
	require.Contains(t, rr.Header().Get("Location"), "http://localhost/callback")
	current, err := user.UserByID(usr.ID)
	require.NoError(t, err)
	require.True(t, current.IsEmailVerified)
}

func TestResendCapacityAndErrorsPreserveGenericResponseAndReleaseSlots(t *testing.T) {
	withVerificationTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.SmtpHost = "smtp.example.test" })
	usr, err := user.CreateUser("resend-probe", "Password123!", "resend@example.com")
	require.NoError(t, err)
	require.NoError(t, user.SetEmailVerificationToken(usr.ID, "existing-hash", time.Now().Add(time.Hour)))
	slots := make(chan struct{}, 1)
	slots <- struct{}{}
	rr := httptest.NewRecorder()
	handleResendVerification(rr, privacyResendRequest(), func(string, string) error { panic("busy sender must not start") }, slots)
	require.Equal(t, http.StatusOK, rr.Code)
	var stored string
	require.NoError(t, db.GetDB().QueryRow("SELECT email_verification_token FROM users WHERE id=?", usr.ID).Scan(&stored))
	require.Equal(t, "existing-hash", stored, "overload must leave the existing link usable")
	generic := rr.Body.String()
	<-slots
	// Failed persistence returns the reserved slot before the handler returns.
	_, err = db.GetDB().Exec("CREATE TRIGGER fail_resend BEFORE UPDATE OF email_verification_token ON users BEGIN SELECT RAISE(ABORT,'injected failure'); END")
	require.NoError(t, err)
	failed := httptest.NewRecorder()
	handleResendVerification(failed, privacyResendRequest(), func(string, string) error { panic("failed storage must not send") }, slots)
	require.Equal(t, generic, failed.Body.String())
	require.Empty(t, slots)
	_, err = db.GetDB().Exec("DROP TRIGGER fail_resend")
	require.NoError(t, err)
	// Even an SMTP error returns the slot and cannot alter the sent-page response.
	sent := make(chan struct{})
	delivered := httptest.NewRecorder()
	handleResendVerification(delivered, privacyResendRequest(), func(string, string) error {
		defer close(sent)
		return errors.New("injected SMTP failure")
	}, slots)
	require.Equal(t, generic, delivered.Body.String())
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("sender did not run")
	}
	require.Eventually(t, func() bool { return len(slots) == 0 }, time.Second, time.Millisecond)
	require.NoError(t, db.GetDB().QueryRow("SELECT email_verification_token FROM users WHERE id=?", usr.ID).Scan(&stored))
	require.NotEqual(t, "existing-hash", stored, "delivery can resume once capacity returns")
}
