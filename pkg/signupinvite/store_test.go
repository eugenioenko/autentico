package signupinvite

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/utils"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestSharedLimitAndRollback(t *testing.T) {
	testutils.WithTestDB(t)
	hash := utils.HashToken("shared-secret")
	_, err := db.GetDB().Exec("INSERT INTO signup_invites(id,token_hash,kind,delivery_method,max_uses) VALUES('test',?,'shared','link',2)", hash)
	require.NoError(t, err)
	i := Invite{ID: "test", hash: hash}
	failed := errors.New("account insert failed")
	require.ErrorIs(t, i.Redeem(t.Context(), "", func(*sql.Tx, bool) error { return failed }), failed)
	done := make(chan error, 5)
	for n := 0; n < 5; n++ {
		go func() {
			done <- i.Redeem(t.Context(), "", func(_ *sql.Tx, verified bool) error {
				if verified {
					return errors.New("shared link verified an address")
				}
				return nil
			})
		}()
	}
	wins := 0
	for n := 0; n < 5; n++ {
		if err := <-done; err == nil {
			wins++
		} else {
			require.ErrorIs(t, err, ErrUnavailable)
		}
	}
	require.Equal(t, 2, wins)
}
func TestPersonalEmailBindingAndRevocation(t *testing.T) {
	testutils.WithTestDB(t)
	hash := utils.HashToken("personal-secret")
	_, err := db.GetDB().Exec("INSERT INTO signup_invites(id,token_hash,kind,delivery_method,email,max_uses,expires_at) VALUES('test',?,'personal','email','test@example.org',1,datetime('now','+1 day'))", hash)
	require.NoError(t, err)
	r := httptest.NewRequest("GET", "/", nil)
	_, err = Resolve(r, config.AccountClientID, "test")
	require.ErrorIs(t, err, ErrUnavailable)
	r.AddCookie(cookie("personal-secret", 1800))
	_, err = Resolve(r, "different-client", "test")
	require.ErrorIs(t, err, ErrUnavailable)
	i, err := Resolve(r, config.AccountClientID, "test")
	require.NoError(t, err)
	create := func(_ *sql.Tx, verified bool) error { require.True(t, verified); return nil }
	require.ErrorIs(t, i.Redeem(t.Context(), "other@example.org", create), ErrUnavailable)
	require.NoError(t, i.Redeem(t.Context(), i.Email, create))
	require.ErrorIs(t, i.Redeem(t.Context(), i.Email, create), ErrUnavailable)
	_, err = db.GetDB().Exec("UPDATE signup_invites SET use_count=0,revoked_at=CURRENT_TIMESTAMP")
	require.NoError(t, err)
	require.ErrorIs(t, i.Redeem(t.Context(), i.Email, create), ErrUnavailable)
	_, err = db.GetDB().Exec("UPDATE signup_invites SET revoked_at=NULL,expires_at=datetime('now','-1 minute')")
	require.NoError(t, err)
	require.ErrorIs(t, i.Redeem(t.Context(), i.Email, create), ErrUnavailable)
}
func TestExplicitLimits(t *testing.T) {
	now := time.Now()
	for _, p := range []CreateRequest{{Kind: "shared", Delivery: "link"}, {Kind: "shared", Delivery: "link", Unlimited: true, Email: "a@example.org"}, {Kind: "personal", Delivery: "link", NeverExpires: true}, {Kind: "personal", Delivery: "email"}} {
		require.Error(t, p.validate(now))
	}
	p := CreateRequest{Kind: "personal", Delivery: "link"}
	require.NoError(t, p.validate(now))
	require.Equal(t, 1, *p.MaxUses)
	require.Equal(t, now.Add(7*24*time.Hour), *p.Expires)
	p = CreateRequest{Kind: "shared", Delivery: "link", Unlimited: true, NeverExpires: true}
	require.NoError(t, p.validate(now))
	require.Nil(t, p.Expires)
	require.Nil(t, p.MaxUses)
}

func TestListFiltersSearchAndPagination(t *testing.T) {
	testutils.WithTestDB(t)
	for _, entry := range []struct{ id, email string }{{"a", "first@example.org"}, {"b", "second@example.org"}, {"c", "outside@example.com"}} {
		_, err := db.GetDB().Exec(`INSERT INTO signup_invites(id,token_hash,kind,delivery_method,email,max_uses,created_at,expires_at)
 VALUES(?,?,'personal','email',?,1,'2025-04-02 10:00:00','2099-10-01 00:00:00')`, entry.id, entry.id, entry.email)
		require.NoError(t, err)
	}
	_, err := db.GetDB().Exec("UPDATE signup_invites SET revoked_at=CURRENT_TIMESTAMP WHERE id='c'")
	require.NoError(t, err)
	query := func(q string) ListResponse {
		t.Helper()
		w := httptest.NewRecorder()
		HandleList(w, httptest.NewRequest("GET", "/admin/api/signup-invites?"+q, nil))
		require.Equal(t, 200, w.Code, w.Body.String())
		var envelope struct{ Data ListResponse }
		require.NoError(t, json.NewDecoder(w.Body).Decode(&envelope))
		return envelope.Data
	}
	q := "kind=personal&delivery_method=email&status=active&search=example.org&created_at_from=2025-04-02T11:00:00%2B02:00&created_at_to=2025-04-02T11:00:00Z&limit=1&order=desc"
	first := query(q)
	require.Equal(t, 2, first.Total)
	require.Len(t, first.Items, 1)
	require.Equal(t, "b", first.Items[0].ID)
	next := query(q + "&offset=1")
	require.Equal(t, "a", next.Items[0].ID)
	empty := query(q + "&offset=2")
	require.Empty(t, empty.Items)
	require.Equal(t, 2, empty.Total)
	revoked := query("status=revoked&search=c")
	require.Len(t, revoked.Items, 1)
	require.Equal(t, "revoked", revoked.Items[0].Status)
	require.Empty(t, query("delivery_method=link").Items)
	w := httptest.NewRecorder()
	HandleList(w, httptest.NewRequest("GET", "/admin/api/signup-invites?created_at_from=invalid", nil))
	require.Equal(t, 400, w.Code)
}
