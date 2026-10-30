package groupclaim

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/group"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestValidateGroupClaims(t *testing.T) {
	for _, name := range []string{"role", "email", "tier", "department.name", "https://app.example.com/tier", "_private"} {
		require.NoError(t, ValidateGroupClaimRequest(GroupClaimRequest{Name: name, Value: ""}), name)
	}
	for _, name := range []string{"", "1role", "has space", "bad$", strings.Repeat("a", 129)} {
		require.Error(t, ValidateGroupClaimRequest(GroupClaimRequest{Name: name}), name)
	}
	require.NoError(t, ValidateGroupClaimRequest(GroupClaimRequest{Name: "tier", Value: strings.Repeat("é", 4096)}))
	require.Error(t, ValidateGroupClaimRequest(GroupClaimRequest{Name: "tier", Value: strings.Repeat("a", 4097)}))
}

func claimRequest(method, id, name, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/admin/api/groups/"+id+"/claims", strings.NewReader(body))
	req.SetPathValue("id", id)
	req.SetPathValue("name", name)
	rr := httptest.NewRecorder()
	switch method {
	case "GET":
		HandleListGroupClaims(rr, req)
	case "POST":
		HandleUpsertGroupClaim(rr, req)
	case "DELETE":
		HandleDeleteGroupClaim(rr, req)
	}
	return rr
}

func TestGroupClaimsCRUDAndAudit(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
	testutils.InsertTestGroup(t, "g1", "app1")
	testutils.InsertTestGroup(t, "g2", "app2")
	require.Equal(t, http.StatusOK, claimRequest("GET", "g1", "", "").Code)
	for _, value := range []string{"private-original", "private-replacement"} {
		payload, err := json.Marshal(GroupClaimRequest{Name: " role ", Value: value})
		require.NoError(t, err)
		require.Equal(t, http.StatusCreated, claimRequest("POST", "g1", "", string(payload)).Code)
	}
	claims, err := ClaimsByGroupID("g1")
	require.NoError(t, err)
	require.Len(t, claims, 1)
	require.Equal(t, "role", claims[0].Name)
	require.Equal(t, "private-replacement", claims[0].Value)
	other, err := ClaimsByGroupID("g2")
	require.NoError(t, err)
	require.Empty(t, other)
	require.Equal(t, http.StatusNotFound, claimRequest("DELETE", "g2", "role", "").Code)
	require.Equal(t, http.StatusOK, claimRequest("DELETE", "g1", "role", "").Code)
	require.Equal(t, http.StatusNotFound, claimRequest("DELETE", "g1", "role", "").Code)
	rows, err := db.GetDB().Query(`SELECT event, target_type, target_id, detail FROM audit_logs ORDER BY event`)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	var events []string
	for rows.Next() {
		var event, targetType, targetID, detail string
		require.NoError(t, rows.Scan(&event, &targetType, &targetID, &detail))
		require.Equal(t, "group", targetType)
		require.Equal(t, "g1", targetID)
		require.JSONEq(t, `{"claim_name":"role"}`, detail)
		events = append(events, event)
	}
	require.NoError(t, rows.Err())
	require.Equal(t, []string{"group_claim_deleted", "group_claim_upserted", "group_claim_upserted"}, events)
}

func TestGroupClaimsRejectedRequests(t *testing.T) {
	for _, tc := range []struct {
		method, id, name, body string
		status                 int
	}{
		{"GET", "missing", "", "", 404},
		{"GET", "", "", "", 400},
		{"POST", "missing", "", `{"name":"tier","value":"x"}`, 404},
		{"POST", "", "", `{"name":"tier"}`, 400},
		{"POST", "g1", "", `{`, 400},
		{"POST", "g1", "", `{"name":"tier","value":true}`, 400},
		{"POST", "g1", "", `{"name":"bad name","value":"x"}`, 400},
		{"POST", "g1", "", `{"value":"x"}`, 400},
		{"DELETE", "", "tier", "", 400},
		{"DELETE", "g1", "", "", 400},
		{"DELETE", "missing", "tier", "", 404},
	} {
		t.Run(tc.method+tc.id+tc.body, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.InsertTestGroup(t, "g1", "app1")
			rr := claimRequest(tc.method, tc.id, tc.name, tc.body)
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count))
			require.Zero(t, count)
		})
	}
}

func TestGroupClaimOwnershipAndCascade(t *testing.T) {
	testutils.WithTestDB(t)
	require.ErrorContains(t, UpsertClaim("missing", "tier", "x"), "group not found")
	testutils.InsertTestGroup(t, "g1", "app1")
	require.NoError(t, UpsertClaim("g1", "tier", "x"))
	require.NoError(t, group.DeleteGroup("g1"))
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM group_claims`).Scan(&count))
	require.Zero(t, count)
}

func TestGroupClaimsStorageFailures(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestGroup(t, "g1", "app1")
	_, err := db.GetDB().Exec(`DROP TABLE group_claims`)
	require.NoError(t, err)
	for _, method := range []string{"GET", "POST", "DELETE"} {
		rr := claimRequest(method, "g1", "tier", `{"name":"tier","value":"x"}`)
		require.Equal(t, 500, rr.Code, rr.Body.String())
	}
	var count int
	require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count))
	require.Zero(t, count)
}
