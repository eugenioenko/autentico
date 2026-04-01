package audit

import (
	"testing"

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
