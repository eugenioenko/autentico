package federation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRequirementOperatorsAndStrictTypes(t *testing.T) {
	for _, tc := range []struct {
		name, operator   string
		expected, actual any
		present, pass    bool
		reason           string
	}{
		{"string equal", "equals", "ok", "ok", true, true, "matched"},
		{"case sensitive", "equals", "ok", "OK", true, false, "value_mismatch"},
		{"boolean true", "equals", true, true, true, true, "matched"},
		{"boolean false", "equals", false, false, true, true, "matched"},
		{"no coercion", "equals", true, "true", true, false, "wrong_type"},
		{"no string coercion", "not_equals", "true", true, true, false, "wrong_type"},
		{"not equal", "not_equals", "suspended", "active", true, true, "matched"},
		{"negative bool", "not_equals", true, false, true, true, "matched"},
		{"negative equal", "not_equals", "suspended", "suspended", true, false, "value_mismatch"},
		{"regex search", "regex", "company", "mycompany.net", true, true, "matched"},
		{"regex anchors", "regex", "^company$", "mycompany.net", true, false, "value_mismatch"},
		{"negative regex", "not_regex", "^suspended$", "active", true, true, "matched"},
		{"regex denies", "not_regex", "company", "mycompany.net", true, false, "value_mismatch"},
		{"array", "not_equals", "x", []any{"x"}, true, false, "wrong_type"},
		{"object", "not_regex", "x", map[string]any{"a": "b"}, true, false, "wrong_type"},
		{"number", "not_equals", "1", json.Number("1"), true, false, "wrong_type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rules := ClaimRequirements{{Claim: "claim", Match: tc.operator, Value: tc.expected}}
			claims := map[string]any{}
			if tc.present {
				claims["claim"] = tc.actual
			}
			result := EvaluateClaimRequirements(rules, claims)
			require.Equal(t, tc.pass, result.Passed)
			require.Len(t, result.Results, 1)
			require.Equal(t, tc.reason, result.Results[0].Reason)
		})
	}
	for _, operator := range []string{"equals", "not_equals", "regex", "not_regex"} {
		for _, claims := range []map[string]any{{}, {"claim": nil}, {"claim": 123}, {"claim": []any{}}} {
			require.False(t, EvaluateClaimRequirements(ClaimRequirements{{Claim: "claim", Match: operator, Value: "x"}}, claims).Passed)
		}
	}
}

func TestRequirementsAllRowsLiteralNamesAndDiagnostics(t *testing.T) {
	rules := ClaimRequirements{{"email", "regex", `^[^@]+@mycompany\.com$`}, {"email_verified", "equals", true}, {"status", "not_equals", "suspended"}}
	claims := map[string]any{"email": "member@mycompany.com", "email_verified": true, "status": "active", "extra": "ignored"}
	require.True(t, EvaluateClaimRequirements(rules, claims).Passed)
	claims["email_verified"] = false
	result := EvaluateClaimRequirements(rules, claims)
	require.False(t, result.Passed)
	for i, row := range result.Results {
		require.Equal(t, i, row.Index)
		require.Equal(t, rules[i].Claim, row.Claim)
	}
	require.False(t, result.Results[1].Passed)
	require.True(t, result.Results[0].Passed)
	require.True(t, result.Results[2].Passed)
	raw, err := json.Marshal(result)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "member@mycompany.com")
	require.NotContains(t, string(raw), "suspended")
	require.True(t, EvaluateClaimRequirements(nil, claims).Passed)
	require.False(t, EvaluateClaimRequirements(ClaimRequirements{{"org.name", "equals", "x"}}, map[string]any{"org": map[string]any{"name": "x"}}).Passed)
	require.True(t, EvaluateClaimRequirements(ClaimRequirements{{"org.name", "equals", "x"}}, map[string]any{"org.name": "x"}).Passed)
}

func TestInvalidRequirementsNeverMatchAndCannotBeEncoded(t *testing.T) {
	for _, rule := range []ClaimRequirement{
		{"", "equals", "x"}, {" email", "equals", "x"}, {"x\n", "equals", "x"}, {strings.Repeat("x", 257), "equals", "x"},
		{"x", "unknown", "x"}, {"x", "equals", nil}, {"x", "equals", 1}, {"x", "equals", []string{"x"}},
		{"x", "regex", true}, {"x", "regex", "*mycompany.com"}, {"x", "not_regex", "(?=x)"},
		{"x", "regex", strings.Repeat("x", 1025)}, {"x", "equals", strings.Repeat("x", 4097)},
	} {
		rules := ClaimRequirements{rule}
		require.Error(t, ValidateClaimRequirements(rules))
		_, err := encodeRequirements(rules)
		require.Error(t, err)
		require.False(t, EvaluateClaimRequirements(rules, map[string]any{"x": "x"}).Passed)
	}
	require.Error(t, ValidateClaimRequirements(make(ClaimRequirements, 33)))
	for _, raw := range []string{`null`, `{}`, `true`, `[null]`, `[{"claim":"x","claim":"y","match":"equals","value":"x"}]`, `[{"claim":"x","match":"equals","value":"x","typo":true}]`, "[{\"claim\":\"\xff\",\"match\":\"equals\",\"value\":\"x\"}]"} {
		var rules ClaimRequirements
		require.Error(t, json.Unmarshal([]byte(raw), &rules), raw)
	}
}

func TestClaimsObjectRejectsMalformedNullAndDuplicateNames(t *testing.T) {
	for _, raw := range []string{`null`, `[]`, `true`, `"claims"`, `{broken`, `{} {}`, `{"email":"first","email":"second"}`} {
		_, err := decodeClaimObject([]byte(raw))
		require.Error(t, err, raw)
	}
	claims, err := decodeClaimObject([]byte(`{"verified":false,"email":"x","number":1,"null":null}`))
	require.NoError(t, err)
	require.Equal(t, false, claims["verified"])
	require.IsType(t, json.Number(""), claims["number"])
}
