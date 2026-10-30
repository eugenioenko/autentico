package userclaim_test

import (
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/group"
	"github.com/eugenioenko/autentico/pkg/groupclaim"
	"github.com/eugenioenko/autentico/pkg/userclaim"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestEffectiveClaimsInheritanceAndIndividualOverrides(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "alice")
	testutils.InsertTestUser(t, "bob")
	for _, name := range []string{"app1", "app2"} {
		testutils.InsertTestGroup(t, name, name)
		testutils.InsertTestGroupMembership(t, "alice", name)
		require.NoError(t, groupclaim.UpsertClaim(name, "role", "viewer"))
	}
	require.NoError(t, userclaim.UpsertClaim("alice", "app1.role", "editor"))
	require.NoError(t, userclaim.UpsertClaim("alice", "department", "support"))
	require.NoError(t, userclaim.UpsertClaim("bob", "app1.role", "auditor"))
	resolve := func(want map[string]string) {
		t.Helper()
		got, err := userclaim.EffectiveClaimMapByUserID("alice")
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	resolve(map[string]string{"app1.role": "editor", "app2.role": "viewer", "department": "support"})
	direct, err := userclaim.ClaimsByUserID("alice")
	require.NoError(t, err)
	require.Len(t, direct, 2)
	require.NoError(t, userclaim.DeleteClaim("alice", "app1.role"))
	resolve(map[string]string{"app1.role": "viewer", "app2.role": "viewer", "department": "support"})
	require.NoError(t, group.UpdateGroup("app1", group.GroupUpdateRequest{Name: "renamed"}))
	resolve(map[string]string{"renamed.role": "viewer", "app2.role": "viewer", "department": "support"})
	require.NoError(t, group.RemoveMember("app1", "alice"))
	resolve(map[string]string{"app2.role": "viewer", "department": "support"})
	require.NoError(t, groupclaim.DeleteClaim("app2", "role"))
	resolve(map[string]string{"department": "support"})
	bob, err := userclaim.EffectiveClaimMapByUserID("bob")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"app1.role": "auditor"}, bob)
}

func TestEffectiveClaimsProtectReservedNamesAndEmptyOverrides(t *testing.T) {
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "alice")
	testutils.InsertTestGroup(t, "g", "app1")
	testutils.InsertTestGroupMembership(t, "alice", "g")
	require.NoError(t, groupclaim.UpsertClaim("g", "role", "admin"))
	require.NoError(t, userclaim.UpsertClaim("alice", "app1.role", ""))
	for _, name := range []string{"sub", "role", "email", "cnf", "Email"} {
		require.NoError(t, userclaim.UpsertClaim("alice", name, "forged"))
	}
	got, err := userclaim.EffectiveClaimMapByUserID("alice")
	require.NoError(t, err)
	require.Equal(t, map[string]string{"app1.role": ""}, got)
	_, err = db.GetDB().Exec(`DROP TABLE group_claims`)
	require.NoError(t, err)
	_, err = userclaim.EffectiveClaimMapByUserID("alice")
	require.Error(t, err)
}

func TestIndividualClaimCanOverrideEveryValidGroupPrefix(t *testing.T) {
	for _, prefix := range []string{"app1", "123", "-team", "_team", strings.Repeat("g", 100)} {
		name := prefix + "." + strings.Repeat("c", 128)
		require.NoError(t, userclaim.ValidateUserClaimRequest(userclaim.UserClaimRequest{Name: name, Value: "override"}), name)
	}
	require.Error(t, userclaim.ValidateUserClaimRequest(userclaim.UserClaimRequest{Name: "g." + strings.Repeat("c", 228)}))
}
