package userclaim_test

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/groupclaim"
	"github.com/eugenioenko/autentico/pkg/userclaim"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func setupMergeFixture(t *testing.T) {
	t.Helper()
	testutils.WithTestDB(t)
	testutils.InsertTestUser(t, "alice")
	for _, name := range []string{"app1_admin", "app1_user", "office", "vpn"} {
		testutils.InsertTestGroup(t, name, name)
	}
	require.NoError(t, groupclaim.UpsertClaim("app1_admin", "app1.type", "admin"))
	require.NoError(t, groupclaim.UpsertClaim("app1_user", "app1.type", "user"))
	require.NoError(t, groupclaim.UpsertClaim("office", "allowed_network", "10.20.0.0/16"))
	require.NoError(t, groupclaim.UpsertClaim("vpn", "allowed_network", "10.99.0.0/24"))
}

func resolveClaims(t *testing.T, userID string) map[string]any {
	t.Helper()
	got, err := userclaim.EffectiveClaimsByUserID(userID)
	require.NoError(t, err)
	return got
}

func TestEffectiveClaimsDefaultKeepsGroupPrefixedStrings(t *testing.T) {
	setupMergeFixture(t)
	testutils.InsertTestGroupMembership(t, "alice", "app1_user")
	testutils.InsertTestGroupMembership(t, "alice", "office")
	require.Equal(t, map[string]any{
		"app1_user.app1.type":    "user",
		"office.allowed_network": "10.20.0.0/16",
	}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeSingleGroupIsArray(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	testutils.InsertTestGroupMembership(t, "alice", "app1_user")
	require.Equal(t, map[string]any{"app1.type": []string{"user"}}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeCombinesSortedUniqueValues(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	testutils.InsertTestGroup(t, "branch", "branch")
	require.NoError(t, groupclaim.UpsertClaim("branch", "allowed_network", "10.20.0.0/16"))
	for _, g := range []string{"vpn", "office", "branch", "app1_user", "app1_admin"} {
		testutils.InsertTestGroupMembership(t, "alice", g)
	}
	require.Equal(t, map[string]any{
		"app1.type":       []string{"admin", "user"},
		"allowed_network": []string{"10.20.0.0/16", "10.99.0.0/24"},
	}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeKeepsEmptyValues(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	testutils.InsertTestGroup(t, "blank", "blank")
	require.NoError(t, groupclaim.UpsertClaim("blank", "app1.type", ""))
	testutils.InsertTestGroupMembership(t, "alice", "blank")
	testutils.InsertTestGroupMembership(t, "alice", "app1_user")
	require.Equal(t, map[string]any{"app1.type": []string{"", "user"}}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeIndividualOverrides(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	testutils.InsertTestGroupMembership(t, "alice", "app1_admin")
	testutils.InsertTestGroupMembership(t, "alice", "app1_user")
	testutils.InsertTestGroupMembership(t, "alice", "office")
	require.NoError(t, userclaim.UpsertClaim("alice", "app1.type", "owner"))
	require.NoError(t, userclaim.UpsertClaim("alice", "office.allowed_network", "0.0.0.0/0"))
	require.NoError(t, userclaim.UpsertClaim("alice", "department", "support"))
	require.Equal(t, map[string]any{
		"app1.type":              []string{"owner"},
		"allowed_network":        []string{"10.20.0.0/16"},
		"office.allowed_network": "0.0.0.0/0",
		"department":             "support",
	}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeProtectsReservedNames(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	for _, name := range []string{"role", "sub", "email", "groups"} {
		require.NoError(t, groupclaim.UpsertClaim("app1_user", name, "forged"))
	}
	testutils.InsertTestGroupMembership(t, "alice", "app1_user")
	require.Equal(t, map[string]any{"app1.type": []string{"user"}}, resolveClaims(t, "alice"))
}

func TestEffectiveClaimsMergeNonMemberAndFailure(t *testing.T) {
	setupMergeFixture(t)
	testutils.WithConfigOverride(t, func() { config.Values.MergeGroupClaims = true })
	require.Empty(t, resolveClaims(t, "alice"))
	_, err := db.GetDB().Exec(`DROP TABLE group_claims`)
	require.NoError(t, err)
	_, err = userclaim.EffectiveClaimsByUserID("alice")
	require.Error(t, err)
}
