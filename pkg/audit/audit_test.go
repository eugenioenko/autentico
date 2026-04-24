package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/model"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testActor implements the Actor interface for tests.
type testActor struct {
	id       string
	username string
}

func (a *testActor) GetID() string      { return a.id }
func (a *testActor) GetUsername() string { return a.username }

func listParams(sort, order, search string, limit, offset int) api.ListParams {
	return api.ListParams{
		Sort:   sort,
		Order:  order,
		Search: search,
		Limit:  limit,
		Offset: offset,
	}
}

func listParamsWithFilter(event string, limit, offset int) api.ListParams {
	p := api.ListParams{Limit: limit, Offset: offset}
	if event != "" {
		p.Filters = map[string]string{"event": event}
	}
	return p
}

func TestLog_Disabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "0"
	})

	Log(EventLoginSuccess, &testActor{"user1", "alice"}, TargetUser, "user1", nil, "127.0.0.1")

	var count int
	err := db.GetDB().QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "no events should be recorded when disabled")
}

func TestLog_Enabled(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "-1"
	})

	Log(EventLoginSuccess, &testActor{"user1", "alice"}, TargetUser, "user1", Detail("method", "password"), "192.168.1.1")

	var count int
	err := db.GetDB().QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	var log AuditLog
	err = db.GetDB().QueryRow(
		"SELECT id, event, actor_id, actor_username, target_type, target_id, detail, ip_address FROM audit_logs",
	).Scan(&log.ID, &log.Event, &log.ActorID, &log.ActorUsername, &log.TargetType, &log.TargetID, &log.Detail, &log.IPAddress)
	require.NoError(t, err)

	assert.NotEmpty(t, log.ID)
	assert.Equal(t, string(EventLoginSuccess), log.Event)
	assert.NotNil(t, log.ActorID)
	assert.Equal(t, "user1", *log.ActorID)
	assert.Equal(t, "alice", log.ActorUsername)
	assert.Equal(t, "user", log.TargetType)
	assert.Equal(t, "user1", log.TargetID)
	assert.Equal(t, `{"method":"password"}`, log.Detail)
	assert.Equal(t, "192.168.1.1", log.IPAddress)
}

func TestLog_NilActor(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "-1"
	})

	Log(EventLoginFailed, nil, TargetUser, "", Detail("reason", "invalid password"), "10.0.0.1")

	var actorID *string
	var actorUsername string
	err := db.GetDB().QueryRow("SELECT actor_id, actor_username FROM audit_logs").Scan(&actorID, &actorUsername)
	require.NoError(t, err)
	assert.Nil(t, actorID, "actor_id should be NULL when actor is nil")
	assert.Equal(t, "", actorUsername)
}

func TestLog_EmptyRetentionString(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = ""
	})

	Log(EventLoginSuccess, &testActor{"user1", "alice"}, TargetUser, "user1", nil, "127.0.0.1")

	var count int
	_ = db.GetDB().QueryRow("SELECT COUNT(*) FROM audit_logs").Scan(&count)
	assert.Equal(t, 0, count)
}

func TestListAuditLogs_Pagination(t *testing.T) {
	testutils.WithTestDB(t)

	for i := 0; i < 5; i++ {
		_, err := db.GetDB().Exec(
			"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
			"id"+string(rune('0'+i)), EventLoginSuccess,
		)
		require.NoError(t, err)
	}

	logs, total, err := ListAuditLogsWithParams(listParams("", "", "", 2, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, logs, 2)

	logs2, total2, err := ListAuditLogsWithParams(listParams("", "", "", 2, 2), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 5, total2)
	assert.Len(t, logs2, 2)

	logs3, _, err := ListAuditLogsWithParams(listParams("", "", "", 2, 4), "", nil)
	require.NoError(t, err)
	assert.Len(t, logs3, 1)
}

func TestListAuditLogs_FilterByEvent(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
		"e1", EventLoginSuccess,
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
		"e2", EventLoginFailed,
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
		"e3", EventLoginSuccess,
	)

	logs, total, err := ListAuditLogsWithParams(listParamsWithFilter(string(EventLoginSuccess), 50, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, logs, 2)
	for _, l := range logs {
		assert.Equal(t, string(EventLoginSuccess), l.Event)
	}
}

func TestListAuditLogs_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	logs, total, err := ListAuditLogsWithParams(listParams("", "", "", 50, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Len(t, logs, 0)
	assert.NotNil(t, logs, "should return empty slice, not nil")
}

func TestListAuditLogs_Search(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '10.0.0.1')",
		"s1", EventLoginSuccess, "alice",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '192.168.1.1')",
		"s2", EventLoginFailed, "bob",
	)

	logs, total, err := ListAuditLogsWithParams(listParams("", "", "alice", 50, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "alice", logs[0].ActorUsername)

	logs2, total2, err := ListAuditLogsWithParams(listParams("", "", "192.168", 50, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, total2)
	assert.Len(t, logs2, 1)
	assert.Equal(t, "bob", logs2[0].ActorUsername)
}

func TestListAuditLogs_Sort(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"t1", EventLoginSuccess, "2026-01-01T00:00:00Z",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"t2", EventUserCreated, "2026-01-02T00:00:00Z",
	)

	logs, _, err := ListAuditLogsWithParams(listParams("event", "asc", "", 50, 0), "", nil)
	require.NoError(t, err)
	assert.Equal(t, string(EventLoginSuccess), logs[0].Event)
	assert.Equal(t, string(EventUserCreated), logs[1].Event)
}

func TestListAuditLogs_DateRange(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"d1", EventLoginSuccess, "2026-01-01T00:00:00Z",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"d2", EventLoginSuccess, "2026-01-15T00:00:00Z",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"d3", EventLoginSuccess, "2026-02-01T00:00:00Z",
	)

	logs, total, err := ListAuditLogsWithParams(
		listParams("", "", "", 50, 0),
		" AND created_at >= ? AND created_at <= ?",
		[]any{"2026-01-10T00:00:00Z", "2026-01-20T00:00:00Z"},
	)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "d2", logs[0].ID)
}

func TestListAuditLogs_FilterByEventAndSearch(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, ?, '', '', '', '')",
		"b1", EventLoginSuccess, "user-a", "alice",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, ?, '', '', '', '')",
		"b2", EventLoginFailed, "user-a", "alice",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, ?, '', '', '', '')",
		"b3", EventLoginSuccess, "user-b", "bob",
	)

	p := listParamsWithFilter(string(EventLoginSuccess), 50, 0)
	p.Search = "alice"
	logs, total, err := ListAuditLogsWithParams(p, "", nil)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "b1", logs[0].ID)
}

// ---------- Detail ----------

func TestDetail_Pairs(t *testing.T) {
	d := Detail("key1", "val1", "key2", "val2")
	assert.Equal(t, "val1", d["key1"])
	assert.Equal(t, "val2", d["key2"])
	assert.Len(t, d, 2)
}

func TestDetail_OddArgs(t *testing.T) {
	d := Detail("key1", "val1", "orphan")
	assert.Equal(t, "val1", d["key1"])
	assert.Len(t, d, 1)
}

func TestDetail_Empty(t *testing.T) {
	d := Detail()
	assert.NotNil(t, d)
	assert.Len(t, d, 0)
}

// ---------- SimpleActor ----------

func TestSimpleActor(t *testing.T) {
	a := SimpleActor{ID: "u123", Username: "alice"}
	assert.Equal(t, "u123", a.GetID())
	assert.Equal(t, "alice", a.GetUsername())
}

// ---------- ActorFromRequest ----------

func TestActorFromRequest_NoHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	actor := ActorFromRequest(req)
	assert.Nil(t, actor)
}

func TestActorFromRequest_MalformedHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "no-space-token")
	actor := ActorFromRequest(req)
	assert.Nil(t, actor)
}

func TestActorFromRequest_InvalidToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-jwt-token")
	actor := ActorFromRequest(req)
	assert.Nil(t, actor)
}

// ---------- ToResponse ----------

func TestAuditLog_ToResponse(t *testing.T) {
	actorID := "user-1"
	now := time.Date(2026, 4, 9, 12, 0, 0, 0, time.UTC)
	log := AuditLog{
		ID:           "log-1",
		Event:        "login_success",
		ActorID:      &actorID,
		ActorUsername: "alice",
		TargetType:   "user",
		TargetID:     "user-1",
		Detail:       `{"method":"password"}`,
		IPAddress:    "10.0.0.1",
		CreatedAt:    now,
	}

	resp := log.ToResponse()
	assert.Equal(t, "log-1", resp.ID)
	assert.Equal(t, "login_success", resp.Event)
	assert.Equal(t, &actorID, resp.ActorID)
	assert.Equal(t, "alice", resp.ActorUsername)
	assert.Equal(t, "user", resp.TargetType)
	assert.Equal(t, "user-1", resp.TargetID)
	assert.Equal(t, `{"method":"password"}`, resp.Detail)
	assert.Equal(t, "10.0.0.1", resp.IPAddress)
	assert.Equal(t, "2026-04-09T12:00:00Z", resp.CreatedAt)
}

func TestAuditLog_ToResponse_NilActorID(t *testing.T) {
	log := AuditLog{
		ID:        "log-2",
		Event:     "login_failed",
		CreatedAt: time.Now(),
	}
	resp := log.ToResponse()
	assert.Nil(t, resp.ActorID)
}

// ---------- HandleListAuditLogs ----------

func TestHandleListAuditLogs_DefaultPagination(t *testing.T) {
	testutils.WithTestDB(t)

	for i := 0; i < 3; i++ {
		_, _ = db.GetDB().Exec(
			"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
			"h"+string(rune('0'+i)), EventLoginSuccess,
		)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 3, body.Data.Total)
	assert.Len(t, body.Data.Items, 3)
}

func TestHandleListAuditLogs_WithFilters(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"f1", EventLoginSuccess, "actor-1",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"f2", EventLoginFailed, "actor-2",
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?event=login_success", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 1, body.Data.Total)
}

func TestHandleListAuditLogs_CustomLimitOffset(t *testing.T) {
	testutils.WithTestDB(t)

	for i := 0; i < 10; i++ {
		_, _ = db.GetDB().Exec(
			"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, '', '', '', '', '')",
			fmt.Sprintf("p%d", i), EventLoginSuccess,
		)
	}

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?limit=3&offset=5", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 10, body.Data.Total)
	assert.Len(t, body.Data.Items, 3)
}

func TestHandleListAuditLogs_InvalidLimitIgnored(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?limit=abc&offset=-1", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleListAuditLogs_LimitExceedsMax(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?limit=999", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestHandleListAuditLogs_EmptyResult(t *testing.T) {
	testutils.WithTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 0, body.Data.Total)
	assert.Len(t, body.Data.Items, 0)
}

func TestHandleListAuditLogs_DateRange(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"dr1", EventLoginSuccess, "2026-01-01T00:00:00Z",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, '', '', '', '', '', ?)",
		"dr2", EventLoginSuccess, "2026-06-15T00:00:00Z",
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?created_at_from=2026-06-01T00:00:00Z&created_at_to=2026-07-01T00:00:00Z", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 1, body.Data.Total)
	assert.Equal(t, "dr2", body.Data.Items[0].ID)
}

func TestHandleListAuditLogs_Search(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '10.0.0.1')",
		"sr1", EventLoginSuccess, "charlie",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '192.168.1.1')",
		"sr2", EventLoginFailed, "dave",
	)

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?search=charlie", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	var body struct {
		Data model.ListResponse[AuditLogResponse] `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 1, body.Data.Total)
	assert.Equal(t, "charlie", body.Data.Items[0].ActorUsername)
}

// ---------- Log edge cases ----------

func TestLog_NilDetail(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "-1"
	})

	Log(EventLogout, &testActor{"u1", "bob"}, TargetSession, "s1", nil, "10.0.0.1")

	var detail string
	err := db.GetDB().QueryRow("SELECT detail FROM audit_logs").Scan(&detail)
	require.NoError(t, err)
	assert.Equal(t, "", detail)
}

func TestLog_ActorWithEmptyID(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "-1"
	})

	Log(EventLoginFailed, &testActor{"", "anonymous"}, TargetUser, "", nil, "10.0.0.1")

	var actorID *string
	err := db.GetDB().QueryRow("SELECT actor_id FROM audit_logs").Scan(&actorID)
	require.NoError(t, err)
	assert.Nil(t, actorID, "empty actor ID should be stored as NULL")
}

func TestLog_DBClosed(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.WithConfigOverride(t, func() {
		config.Values.AuditLogRetentionStr = "-1"
	})
	db.CloseDB()

	// Should not panic, just print an error
	Log(EventLoginSuccess, &testActor{"u1", "alice"}, TargetUser, "u1", nil, "10.0.0.1")
}
