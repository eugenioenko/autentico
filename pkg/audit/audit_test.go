package audit

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testActor implements the Actor interface for tests.
type testActor struct {
	id       string
	username string
}

func (a *testActor) GetID() string       { return a.id }
func (a *testActor) GetUsername() string  { return a.username }

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

	logs, total, err := ListAuditLogs("", "", 2, 0)
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, logs, 2)

	logs2, total2, err := ListAuditLogs("", "", 2, 2)
	require.NoError(t, err)
	assert.Equal(t, 5, total2)
	assert.Len(t, logs2, 2)

	logs3, _, err := ListAuditLogs("", "", 2, 4)
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

	logs, total, err := ListAuditLogs(string(EventLoginSuccess), "", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, logs, 2)
	for _, l := range logs {
		assert.Equal(t, string(EventLoginSuccess), l.Event)
	}
}

func TestListAuditLogs_FilterByActorID(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"a1", EventLoginSuccess, "user-abc",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"a2", EventLoginSuccess, "user-xyz",
	)

	logs, total, err := ListAuditLogs("", "user-abc", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "user-abc", *logs[0].ActorID)
}

func TestListAuditLogs_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	logs, total, err := ListAuditLogs("", "", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, 0, total)
	assert.Len(t, logs, 0)
	assert.NotNil(t, logs, "should return empty slice, not nil")
}

// ---------- Detail ----------

func TestDetail_Pairs(t *testing.T) {
	d := Detail("key1", "val1", "key2", "val2")
	assert.Equal(t, "val1", d["key1"])
	assert.Equal(t, "val2", d["key2"])
	assert.Len(t, d, 2)
}

func TestDetail_OddArgs(t *testing.T) {
	// Odd number of args — last key is silently dropped
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

	// Insert 3 logs
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
		Data struct {
			Data  []AuditLogResponse `json:"data"`
			Total int                `json:"total"`
		} `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 3, body.Data.Total)
	assert.Len(t, body.Data.Data, 3)
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

	req := httptest.NewRequest(http.MethodGet, "/admin/api/audit-logs?event=login_success&actor_id=actor-1", nil)
	rr := httptest.NewRecorder()
	HandleListAuditLogs(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)

	var body struct {
		Data struct {
			Data  []AuditLogResponse `json:"data"`
			Total int                `json:"total"`
		} `json:"data"`
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
		Data struct {
			Data  []AuditLogResponse `json:"data"`
			Total int                `json:"total"`
		} `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 10, body.Data.Total)
	assert.Len(t, body.Data.Data, 3)
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

	// limit > 200 should be ignored (stays at default 50)
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
		Data struct {
			Data  []AuditLogResponse `json:"data"`
			Total int                `json:"total"`
		} `json:"data"`
	}
	err := json.Unmarshal(rr.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, 0, body.Data.Total)
	assert.Len(t, body.Data.Data, 0)
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

// ---------- ListAuditLogs with both filters ----------

func TestListAuditLogs_FilterByEventAndActorID(t *testing.T) {
	testutils.WithTestDB(t)

	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"b1", EventLoginSuccess, "user-a",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"b2", EventLoginFailed, "user-a",
	)
	_, _ = db.GetDB().Exec(
		"INSERT INTO audit_logs (id, event, actor_id, actor_username, target_type, target_id, detail, ip_address) VALUES (?, ?, ?, '', '', '', '', '')",
		"b3", EventLoginSuccess, "user-b",
	)

	logs, total, err := ListAuditLogs(string(EventLoginSuccess), "user-a", 50, 0)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, logs, 1)
	assert.Equal(t, "b1", logs[0].ID)
}
