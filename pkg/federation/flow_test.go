package federation

import (
	"context"
	"database/sql"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/sqliteutil"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

// prepareTestLoginFlow creates the same durable binding as a successful begin.
func prepareTestLoginFlow(t *testing.T, state *FederationState, browser *http.Cookie) (string, *http.Cookie) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/begin", nil)
	if browser != nil {
		r.AddCookie(browser)
	}
	signed, cookie, err := beginLoginFlow(r, state)
	require.NoError(t, err)
	require.NotNil(t, cookie)
	return signed, cookie
}

func flowCallback(cookie *http.Cookie) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/callback", nil)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	return r
}

func flowRowCount(t *testing.T) int {
	t.Helper()
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM federation_login_flows`).Scan(&count))
	return count
}

func TestLoginFlowCookieAndHashStorage(t *testing.T) {
	for _, secure := range []bool{false, true} {
		name := "local HTTP"
		if secure {
			name = "secure host-only"
		}
		t.Run(name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Bootstrap.AuthIdpSessionSecureCookie = secure })
			state := FederationState{ProviderID: "upstream", Nonce: "rp-nonce"}
			before := time.Now()
			signed, cookie := prepareTestLoginFlow(t, &state, nil)
			expectedName := federationBrowserCookie
			if secure {
				expectedName = "__Host-" + expectedName
			}
			require.Equal(t, expectedName, cookie.Name)
			require.Equal(t, "/", cookie.Path)
			require.Empty(t, cookie.Domain)
			require.True(t, cookie.HttpOnly)
			require.Equal(t, secure, cookie.Secure)
			require.Equal(t, http.SameSiteLaxMode, cookie.SameSite)
			require.Equal(t, 600, cookie.MaxAge)
			require.InDelta(t, before.Add(federationFlowLifetime).Unix(), state.ExpiresAt, 1)
			require.True(t, validFlowValue(cookie.Value))
			require.True(t, validFlowValue(state.FlowID))
			require.NotEqual(t, cookie.Value, state.FlowID)
			payload, err := base64.RawURLEncoding.DecodeString(strings.SplitN(signed, ".", 2)[0])
			require.NoError(t, err)
			require.NotContains(t, string(payload), cookie.Value)
			verified, err := VerifyState(signed)
			require.NoError(t, err)
			require.Equal(t, state, *verified)
			require.Equal(t, "rp-nonce", verified.Nonce)
			var browserHash, stateHash string
			var expiry int64
			require.NoError(t, db.GetDB().QueryRow(`SELECT browser_hash,state_hash,expires_at FROM federation_login_flows WHERE flow_id=?`, state.FlowID).Scan(&browserHash, &stateHash, &expiry))
			require.Equal(t, utils.HashSHA256(cookie.Value), browserHash)
			require.Equal(t, utils.HashSHA256(signed), stateHash)
			require.Equal(t, state.ExpiresAt, expiry)
		})
	}
}

func TestLoginFlowRejectsMismatchesWithoutBurningOwnerState(t *testing.T) {
	for _, kind := range []string{"missing cookie", "malformed cookie", "another browser", "altered signed request", "unknown flow", "expired signed state", "legacy state"} {
		t.Run(kind, func(t *testing.T) {
			testutils.WithTestDB(t)
			state := FederationState{ProviderID: "upstream", Nonce: "rp"}
			signed, cookie := prepareTestLoginFlow(t, &state, nil)
			candidate := state
			candidateSigned := signed
			candidateCookie := cookie
			switch kind {
			case "missing cookie":
				candidateCookie = nil
			case "malformed cookie":
				candidateCookie = &http.Cookie{Name: cookie.Name, Value: "invalid"}
			case "another browser":
				value, err := randomFlowValue()
				require.NoError(t, err)
				candidateCookie = &http.Cookie{Name: cookie.Name, Value: value}
			case "altered signed request":
				candidate.Scope = "different"
				candidateSigned, _ = SignState(candidate)
			case "unknown flow":
				value, err := randomFlowValue()
				require.NoError(t, err)
				candidate.FlowID = value
				candidateSigned, _ = SignState(candidate)
			case "legacy state":
				candidate.FlowID = ""
				candidate.ExpiresAt = 0
				candidateSigned, _ = SignState(candidate)
			case "expired signed state":
				candidate.ExpiresAt = time.Now().Add(-time.Second).Unix()
				candidateSigned, _ = SignState(candidate)
			}
			require.ErrorIs(t, consumeLoginFlow(flowCallback(candidateCookie), &candidate, candidateSigned), errInvalidLoginFlow)
			require.Equal(t, 1, flowRowCount(t))
			require.NoError(t, consumeLoginFlow(flowCallback(cookie), &state, signed))
			require.Zero(t, flowRowCount(t))
			require.ErrorIs(t, consumeLoginFlow(flowCallback(cookie), &state, signed), errInvalidLoginFlow)
		})
	}
}

func TestIndependentLoginFlowsReuseBrowserBinding(t *testing.T) {
	testutils.WithTestDB(t)
	first, second := FederationState{ProviderID: "first"}, FederationState{ProviderID: "second"}
	signedFirst, cookieFirst := prepareTestLoginFlow(t, &first, nil)
	signedSecond, cookieSecond := prepareTestLoginFlow(t, &second, cookieFirst)
	require.Equal(t, cookieFirst.Value, cookieSecond.Value)
	require.NotEqual(t, first.FlowID, second.FlowID)
	require.NoError(t, consumeLoginFlow(flowCallback(cookieFirst), &first, signedFirst))
	require.Equal(t, 1, flowRowCount(t))
	require.NoError(t, consumeLoginFlow(flowCallback(cookieFirst), &second, signedSecond))
	require.Zero(t, flowRowCount(t))
}

func TestOnlyOneConcurrentCallbackConsumesLoginFlow(t *testing.T) {
	testutils.WithTestDB(t)
	state := FederationState{}
	signed, cookie := prepareTestLoginFlow(t, &state, nil)
	const attempts = 12
	results := make(chan error, attempts)
	start := make(chan struct{})
	for range attempts {
		go func() { <-start; results <- consumeLoginFlow(flowCallback(cookie), &state, signed) }()
	}
	close(start)
	winners := 0
	for range attempts {
		err := <-results
		if err == nil {
			winners++
		} else {
			require.ErrorIs(t, err, errInvalidLoginFlow)
		}
	}
	require.Equal(t, 1, winners)
	require.Zero(t, flowRowCount(t))
}

func TestFlowStorageFailuresAreAtomicAndConnectionRemainsUsable(t *testing.T) {
	for _, kind := range []string{"delete", "commit"} {
		t.Run(kind, func(t *testing.T) {
			testutils.WithTestDB(t)
			state := FederationState{}
			signed, cookie := prepareTestLoginFlow(t, &state, nil)
			trigger := `CREATE TRIGGER reject_flow BEFORE DELETE ON federation_login_flows BEGIN SELECT RAISE(FAIL,'injected flow failure'); END`
			if kind == "commit" {
				trigger = `CREATE TABLE flow_parent(id INTEGER PRIMARY KEY); CREATE TABLE flow_child(parent_id INTEGER REFERENCES flow_parent(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_flow AFTER DELETE ON federation_login_flows BEGIN INSERT INTO flow_child VALUES(123); END`
			}
			_, err := db.GetDB().Exec(trigger)
			require.NoError(t, err)
			err = consumeLoginFlow(flowCallback(cookie), &state, signed)
			require.Error(t, err)
			require.NotErrorIs(t, err, errInvalidLoginFlow)
			require.Equal(t, 1, flowRowCount(t))
			if kind == "commit" {
				var count int
				require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM flow_child`).Scan(&count))
				require.Zero(t, count)
			}
			_, err = db.GetDB().Exec(`DROP TRIGGER reject_flow`)
			require.NoError(t, err)
			require.NoError(t, consumeLoginFlow(flowCallback(cookie), &state, signed))
			require.Zero(t, flowRowCount(t))
		})
	}
}

func TestFailedFlowCreationReturnsNoCookieOrState(t *testing.T) {
	testutils.WithTestDB(t)
	_, err := db.GetDB().Exec(`CREATE TRIGGER reject_flow BEFORE INSERT ON federation_login_flows BEGIN SELECT RAISE(FAIL,'injected flow creation failure'); END`)
	require.NoError(t, err)
	signed, cookie, err := beginLoginFlow(httptest.NewRequest(http.MethodGet, "/begin", nil), &FederationState{})
	require.Error(t, err)
	require.Empty(t, signed)
	require.Nil(t, cookie)
	require.Zero(t, flowRowCount(t))
}

// withFlowFileDB exercises independent SQLite connections and database reopen.
func withFlowFileDB(t *testing.T) string {
	t.Helper()
	testutils.WithTotpKey(t)
	path := filepath.Join(t.TempDir(), "federation.db")
	_, err := db.InitDB(path)
	require.NoError(t, err)
	t.Cleanup(db.CloseDB)
	return path
}

func TestLoginFlowConsumptionSurvivesDatabaseReopen(t *testing.T) {
	path := withFlowFileDB(t)
	first, second := FederationState{}, FederationState{}
	rawFirst, cookie := prepareTestLoginFlow(t, &first, nil)
	rawSecond, _ := prepareTestLoginFlow(t, &second, cookie)
	require.NoError(t, consumeLoginFlow(flowCallback(cookie), &first, rawFirst))
	db.CloseDB()
	_, err := db.InitDB(path)
	require.NoError(t, err)
	verified, err := VerifyState(rawSecond)
	require.NoError(t, err)
	require.ErrorIs(t, consumeLoginFlow(flowCallback(cookie), &first, rawFirst), errInvalidLoginFlow)
	require.NoError(t, consumeLoginFlow(flowCallback(cookie), verified, rawSecond))
	require.Zero(t, flowRowCount(t))
}

func TestLoginFlowRechecksExpiryAfterExternalSQLiteWriter(t *testing.T) {
	path := withFlowFileDB(t)
	state := FederationState{}
	_, cookie := prepareTestLoginFlow(t, &state, nil)
	state.ExpiresAt = time.Now().Add(2 * time.Second).Unix()
	signed, err := SignState(state)
	require.NoError(t, err)
	_, err = db.GetDB().Exec(`UPDATE federation_login_flows SET state_hash=?,expires_at=? WHERE flow_id=?`, utils.HashSHA256(signed), state.ExpiresAt, state.FlowID)
	require.NoError(t, err)
	uri := sqliteutil.FileURL(path)
	external, err := sql.Open("sqlite", uri.String())
	require.NoError(t, err)
	defer func() { _ = external.Close() }()
	tx, err := external.BeginTx(context.Background(), nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`UPDATE federation_login_flows SET expires_at=expires_at WHERE flow_id=?`, state.FlowID)
	require.NoError(t, err)
	result := make(chan error, 1)
	go func() { result <- consumeLoginFlow(flowCallback(cookie), &state, signed) }()
	select {
	case err := <-result:
		t.Fatalf("callback did not wait for external writer: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	time.Sleep(time.Until(time.Unix(state.ExpiresAt, 0)) + 20*time.Millisecond)
	require.NoError(t, tx.Commit())
	select {
	case err := <-result:
		require.ErrorIs(t, err, errInvalidLoginFlow)
	case <-time.After(6 * time.Second):
		t.Fatal("callback did not finish after writer release")
	}
	require.Equal(t, 1, flowRowCount(t))
}

func TestCanceledFlowConsumptionLeavesOwnerStateUsable(t *testing.T) {
	testutils.WithTestDB(t)
	state := FederationState{}
	signed, cookie := prepareTestLoginFlow(t, &state, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := flowCallback(cookie).WithContext(ctx)
	require.ErrorIs(t, consumeLoginFlow(r, &state, signed), context.Canceled)
	require.Equal(t, 1, flowRowCount(t))
	require.NoError(t, consumeLoginFlow(flowCallback(cookie), &state, signed))
}
