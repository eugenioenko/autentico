package userclaim

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestUserClaimAuditSuccessfulChanges(t *testing.T) {
	for _, retention := range []string{"-1", "0"} {
		t.Run("retention="+retention, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = retention })
			testutils.InsertTestUser(t, "u1")
			for _, value := range []string{"sensitive-original", "sensitive-replacement"} {
				rr := upsertReq(t, "u1", UserClaimRequest{Name: "  tier  ", Value: value})
				require.Equal(t, 201, rr.Code)
			}
			req := httptest.NewRequest("DELETE", "/admin/api/users/u1/claims/tier", nil)
			req.SetPathValue("id", "u1")
			req.SetPathValue("name", "tier")
			rr := httptest.NewRecorder()
			HandleDeleteUserClaim(rr, req)
			require.Equal(t, 200, rr.Code)
			rows, err := db.GetDB().Query(`SELECT event,target_type,target_id,detail FROM audit_logs ORDER BY event`)
			require.NoError(t, err)
			defer func() { _ = rows.Close() }()
			events := []string{}
			for rows.Next() {
				var event, targetType, targetID, detail string
				require.NoError(t, rows.Scan(&event, &targetType, &targetID, &detail))
				require.Equal(t, "user", targetType)
				require.Equal(t, "u1", targetID)
				require.JSONEq(t, `{"claim_name":"tier"}`, detail)
				events = append(events, event)
			}
			require.NoError(t, rows.Err())
			if retention == "0" {
				require.Empty(t, events)
			} else {
				require.Equal(t, []string{"user_claim_deleted", "user_claim_upserted", "user_claim_upserted"}, events)
			}
		})
	}
}

func TestUserClaimAuditRejectedChanges(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, id string
		status                 int
	}{
		{"reserved", "POST", `{"name":"sub","value":"secret"}`, "u1", 400},
		{"unknown user", "POST", `{"name":"tier","value":"secret"}`, "missing", 404},
		{"unknown claim", "DELETE", "", "u1", 404},
		{"database failure", "POST", `{"name":"tier","value":"secret"}`, "u1", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
			testutils.InsertTestUser(t, "u1")
			if tc.name == "database failure" {
				_, err := db.GetDB().Exec(`CREATE TRIGGER fail_claim_insert BEFORE INSERT ON user_claims BEGIN SELECT RAISE(ABORT, 'test failure'); END`)
				require.NoError(t, err)
			}
			req := httptest.NewRequest(tc.method, "/admin/api/users/"+tc.id+"/claims/tier", strings.NewReader(tc.body))
			req.SetPathValue("id", tc.id)
			req.SetPathValue("name", "tier")
			rr := httptest.NewRecorder()
			if tc.method == "POST" {
				HandleUpsertUserClaim(rr, req)
			} else {
				HandleDeleteUserClaim(rr, req)
			}
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count))
			require.Zero(t, count)
		})
	}
}
