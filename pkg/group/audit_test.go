package group

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestGroupAuditSuccessfulChanges(t *testing.T) {
	for _, retention := range []string{"-1", "0"} {
		t.Run("retention="+retention, func(t *testing.T) {
			for _, tc := range []struct {
				event, method, body string
				handler             http.HandlerFunc
				member              bool
				status              int
			}{
				{"group_created", "POST", `{"name":"new-group"}`, HandleCreateGroup, false, 201},
				{"group_updated", "PUT", `{"name":"renamed"}`, HandleUpdateGroup, false, 200},
				{"group_deleted", "DELETE", "", HandleDeleteGroup, false, 200},
				{"group_member_added", "POST", `{"user_id":"u1"}`, HandleAddMember, false, 201},
				{"group_member_removed", "DELETE", "", HandleRemoveMember, true, 200},
			} {
				t.Run(tc.event, func(t *testing.T) {
					testutils.WithTestDB(t)
					testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = retention })
					testutils.InsertTestGroup(t, "g1", "existing")
					testutils.InsertTestUser(t, "u1")
					if tc.member {
						require.NoError(t, AddMember("g1", "u1"))
					}
					req := httptest.NewRequest(tc.method, "/admin/api/groups/g1", strings.NewReader(tc.body))
					req.SetPathValue("id", "g1")
					req.SetPathValue("user_id", "u1")
					req.RemoteAddr = "192.0.2.10:1234"
					rr := httptest.NewRecorder()
					tc.handler(rr, req)
					require.Equal(t, tc.status, rr.Code, rr.Body.String())
					var count int
					require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count))
					if retention == "0" {
						require.Zero(t, count)
						return
					}
					require.Equal(t, 1, count)
					var event, targetType, targetID, detail, ip string
					require.NoError(t, db.GetDB().QueryRow(`SELECT event,target_type,target_id,detail,ip_address FROM audit_logs`).Scan(&event, &targetType, &targetID, &detail, &ip))
					require.Equal(t, tc.event, event)
					require.Equal(t, "group", targetType)
					if tc.event == "group_created" {
						var createdID string
						require.NoError(t, db.GetDB().QueryRow(`SELECT id FROM groups WHERE name='new-group'`).Scan(&createdID))
						require.Equal(t, createdID, targetID)
					} else {
						require.Equal(t, "g1", targetID)
					}
					if strings.HasPrefix(tc.event, "group_member_") {
						require.JSONEq(t, `{"user_id":"u1"}`, detail)
					} else {
						require.Empty(t, detail)
					}
					require.Equal(t, "192.0.2.10", ip)
				})
			}
		})
	}
}

func TestGroupAuditRejectedChanges(t *testing.T) {
	for _, tc := range []struct {
		name, method, body, id string
		handler                http.HandlerFunc
		status                 int
	}{
		{"invalid create", "POST", `{"name":""}`, "g1", HandleCreateGroup, 400},
		{"duplicate create", "POST", `{"name":"existing"}`, "g1", HandleCreateGroup, 409},
		{"missing update", "PUT", `{"name":"renamed"}`, "missing", HandleUpdateGroup, 404},
		{"missing delete", "DELETE", "", "missing", HandleDeleteGroup, 404},
		{"duplicate member", "POST", `{"user_id":"u1"}`, "g1", HandleAddMember, 409},
		{"missing member", "DELETE", "", "missing", HandleRemoveMember, 404},
		{"database failure", "PUT", `{"name":"renamed"}`, "g1", HandleUpdateGroup, 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testutils.WithTestDB(t)
			testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
			testutils.InsertTestGroup(t, "g1", "existing")
			testutils.InsertTestUser(t, "u1")
			require.NoError(t, AddMember("g1", "u1"))
			if tc.name == "database failure" {
				_, err := db.GetDB().Exec(`CREATE TRIGGER fail_group_update BEFORE UPDATE ON groups BEGIN SELECT RAISE(ABORT, 'test failure'); END`)
				require.NoError(t, err)
			}
			req := httptest.NewRequest(tc.method, "/admin/api/groups/"+tc.id, strings.NewReader(tc.body))
			req.SetPathValue("id", tc.id)
			req.SetPathValue("user_id", "u1")
			rr := httptest.NewRecorder()
			tc.handler(rr, req)
			require.Equal(t, tc.status, rr.Code, rr.Body.String())
			var count int
			require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM audit_logs`).Scan(&count))
			require.Zero(t, count, "failed changes must not produce success audit events")
		})
	}
}

// Keep the response contract checked when audit storage itself is unavailable.
func TestGroupAuditStorageFailureDoesNotFailChange(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() { config.Values.AuditLogRetentionStr = "-1" })
	_, err := db.GetDB().Exec(`DROP TABLE audit_logs`)
	require.NoError(t, err)
	req := httptest.NewRequest("POST", "/admin/api/groups", strings.NewReader(`{"name":"saved"}`))
	rr := httptest.NewRecorder()
	HandleCreateGroup(rr, req)
	require.Equal(t, 201, rr.Code)
	var response struct {
		Data GroupResponse `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &response))
	stored, err := GroupByID(response.Data.ID)
	require.NoError(t, err)
	require.Equal(t, "saved", stored.Name)
}
