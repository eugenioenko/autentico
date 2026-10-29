package federation

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/api"
	"github.com/eugenioenko/autentico/pkg/db"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/require"
)

func TestRequirementsProviderPersistencePreservesAndClears(t *testing.T) {
	testutils.WithTestDB(t)
	rules := ClaimRequirements{{"email_verified", "equals", true}, {"email", "regex", `@example\.com$`}}
	require.NoError(t, CreateFederationProvider(FederationProvider{ID: "rules", Name: "Rules", Issuer: "https://issuer.example", ClientID: "client", ClientSecret: "secret", Enabled: true, ClaimRequirements: rules}))
	p, err := FederationProviderByID("rules")
	require.NoError(t, err)
	require.Equal(t, rules, p.ClaimRequirements)
	enabled := true
	update := FederationProviderRequest{Name: "Edited", Issuer: p.Issuer, ClientID: p.ClientID, Enabled: &enabled}
	require.NoError(t, UpdateFederationProvider(p.ID, update))
	p, err = FederationProviderByID(p.ID)
	require.NoError(t, err)
	require.Equal(t, rules, p.ClaimRequirements)
	require.Equal(t, "secret", p.ClientSecret)
	update.ClaimRequirements = ClaimRequirements{{"x", "regex", "["}}
	require.Error(t, UpdateFederationProvider(p.ID, update))
	p, err = FederationProviderByID(p.ID)
	require.NoError(t, err)
	require.Equal(t, rules, p.ClaimRequirements)
	update.ClaimRequirements = ClaimRequirements{}
	raw, err := json.Marshal(update)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"claim_requirements":[]`)
	require.NoError(t, UpdateFederationProvider(p.ID, update))
	p, err = FederationProviderByID(p.ID)
	require.NoError(t, err)
	require.Empty(t, p.ClaimRequirements)
	require.Empty(t, p.ClaimRequirementsError)
}

func TestInvalidStoredRequirementsRemainRepairable(t *testing.T) {
	for _, stored := range []string{`{broken`, `null`, `[{"claim":"email","match":"allow","value":"x"}]`, `[{"claim":"email","match":"regex","value":"["}]`} {
		t.Run(stored, func(t *testing.T) {
			testutils.WithTestDB(t)
			require.NoError(t, CreateFederationProvider(FederationProvider{ID: "bad", Name: "Broken", Issuer: "https://issuer.example", ClientID: "client", ClientSecret: "secret", Enabled: true}))
			_, err := db.GetWriteDB().Exec(`PRAGMA ignore_check_constraints=ON`)
			require.NoError(t, err)
			_, err = db.GetDB().Exec(`UPDATE federation_providers SET claim_requirements=? WHERE id='bad'`, stored)
			require.NoError(t, err)
			_, err = db.GetWriteDB().Exec(`PRAGMA ignore_check_constraints=OFF`)
			require.NoError(t, err)
			p, err := FederationProviderByID("bad")
			require.NoError(t, err)
			require.NotEmpty(t, p.ClaimRequirementsError)
			listed, _, err := ListFederationProvidersWithParams(api.ListParams{})
			require.NoError(t, err)
			require.Len(t, listed, 1)
			require.NotEmpty(t, toProviderResponse(*listed[0]).ClaimRequirementsError)
			// An ordinary GET-to-PUT round trip must never turn a broken policy
			// into an explicit clear, including with echoed read-only fields.
			get := httptest.NewRequest("GET", "/", nil)
			get.SetPathValue("id", "bad")
			response := httptest.NewRecorder()
			HandleGetProvider(response, get)
			require.Equal(t, 200, response.Code)
			var echoed map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &echoed))
			require.NotContains(t, echoed, "claim_requirements")
			require.Contains(t, echoed, "claim_requirements_error")
			echoed["name"] = json.RawMessage(`"Metadata edit"`)
			body, err := json.Marshal(echoed)
			require.NoError(t, err)
			put := httptest.NewRequest("PUT", "/", strings.NewReader(string(body)))
			put.SetPathValue("id", "bad")
			response = httptest.NewRecorder()
			HandleUpdateProvider(response, put)
			require.Equal(t, 200, response.Code, response.Body.String())
			var unchanged string
			require.NoError(t, db.GetDB().QueryRow(`SELECT claim_requirements FROM federation_providers WHERE id='bad'`).Scan(&unchanged))
			require.Equal(t, stored, unchanged)
			enabled := true
			require.NoError(t, UpdateFederationProvider("bad", FederationProviderRequest{Name: "Still blocked", Issuer: p.Issuer, ClientID: p.ClientID, Enabled: &enabled}))
			p, err = FederationProviderByID("bad")
			require.NoError(t, err)
			require.NotEmpty(t, p.ClaimRequirementsError)
			require.NoError(t, UpdateFederationProvider("bad", FederationProviderRequest{Name: "Repaired", Issuer: p.Issuer, ClientID: p.ClientID, Enabled: &enabled, ClaimRequirements: ClaimRequirements{}}))
			p, err = FederationProviderByID("bad")
			require.NoError(t, err)
			require.Empty(t, p.ClaimRequirementsError)
			serialized, err := json.Marshal(toProviderResponse(*p))
			require.NoError(t, err)
			require.Contains(t, string(serialized), `"claim_requirements":[]`)
		})
	}
}

func TestProviderHandlersPreserveExtraFieldCompatibilityAndStrictRules(t *testing.T) {
	testutils.WithTestDB(t)
	body := `{"id":"compat","name":"Compatible","issuer":"https://issuer.example","client_id":"client","client_secret":"secret","future_metadata":{"ignored":true}}`
	w := httptest.NewRecorder()
	HandleCreateProvider(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
	require.Equal(t, 201, w.Code, w.Body.String())
	p, err := FederationProviderByID("compat")
	require.NoError(t, err)
	require.Empty(t, p.ClaimRequirements)
	for _, rules := range []string{`null`, `[{"claim":"org","match":"equals","value":"x","unsupported":true}]`} {
		r := httptest.NewRequest("PUT", "/", strings.NewReader(`{"name":"Rejected","issuer":"https://issuer.example","client_id":"client","future_metadata":true,"claim_requirements":`+rules+`}`))
		r.SetPathValue("id", "compat")
		w = httptest.NewRecorder()
		HandleUpdateProvider(w, r)
		require.Equal(t, 400, w.Code, w.Body.String())
	}
	p, err = FederationProviderByID("compat")
	require.NoError(t, err)
	require.Equal(t, "Compatible", p.Name)
	require.Equal(t, "secret", p.ClientSecret)
}

func TestDraftTesterReadOnlyAndPerRowErrors(t *testing.T) {
	testutils.WithTestDB(t)
	for _, tc := range []struct {
		body   string
		status int
	}{
		{`{"claim_requirements":[{"claim":"x","match":"regex","value":"["}],"claims":{"x":"secret"}}`, 200},
		{`{"claim_requirements":[],"claims":{}}`, 200},
		{`{"claim_requirements":null,"claims":{}}`, 400},
		{`{"claim_requirements":[],"claims":null}`, 400},
		{`{"claim_requirements":[],"claims":{"x":true,"x":false}}`, 400},
		{`{"claim_requirements":[],"claims":{}} {}`, 400},
		{`{"claim_requirements":[],"claims":{},"typo":true}`, 400},
		{`{"claim_requirements":[],"claims":{"x":"` + strings.Repeat("x", 65536) + `"}}`, 400},
	} {
		w := httptest.NewRecorder()
		HandleTestClaimRequirements(w, httptest.NewRequest("POST", "/", strings.NewReader(tc.body)))
		require.Equal(t, tc.status, w.Code, w.Body.String())
		require.Empty(t, w.Result().Cookies())
		if strings.Contains(tc.body, `"value":"["`) {
			var result ClaimTestResult
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
			require.False(t, result.Passed)
			require.Equal(t, "invalid_pattern", result.Results[0].Reason)
			require.NotContains(t, w.Body.String(), "secret")
		}
	}
	for _, table := range []string{"federation_providers", "users", "federated_identities", "idp_sessions", "auth_codes"} {
		var n int
		require.NoError(t, db.GetDB().QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&n))
		require.Zero(t, n, table)
	}
}
