package consent

import "testing"

func boolPtr(v bool) *bool { return &v }

func TestNeedsConsent_NotRequired(t *testing.T) {
	if NeedsConsent(nil, "u1", "c1", "openid", "") {
		t.Error("expected false when consentRequired is nil")
	}
	if NeedsConsent(boolPtr(false), "u1", "c1", "openid", "") {
		t.Error("expected false when consentRequired is false")
	}
}

func TestNeedsConsent_PromptConsent(t *testing.T) {
	if !NeedsConsent(boolPtr(true), "u1", "c1", "openid", "consent") {
		t.Error("expected true when prompt=consent")
	}
	if !NeedsConsent(boolPtr(true), "u1", "c1", "openid", "login consent") {
		t.Error("expected true when prompt contains consent")
	}
}

func TestScopesCovered(t *testing.T) {
	tests := []struct {
		granted   string
		requested string
		covered   bool
	}{
		{"openid profile email", "openid profile", true},
		{"openid profile email", "openid profile email", true},
		{"openid profile", "openid profile email", false},
		{"openid", "profile", false},
		{"openid profile email", "openid", true},
		{"", "openid", false},
		{"openid", "", true},
	}
	for _, tt := range tests {
		if got := scopesCovered(tt.granted, tt.requested); got != tt.covered {
			t.Errorf("scopesCovered(%q, %q) = %v, want %v", tt.granted, tt.requested, got, tt.covered)
		}
	}
}

func TestDescribeScopes(t *testing.T) {
	scopes := DescribeScopes("openid email custom_scope")
	if len(scopes) != 3 {
		t.Fatalf("expected 3 scopes, got %d", len(scopes))
	}
	if scopes[0].Name != "openid" || scopes[0].Description != "Verify your identity" {
		t.Errorf("unexpected scope[0]: %+v", scopes[0])
	}
	if scopes[1].Name != "email" || scopes[1].Description != "View your email address" {
		t.Errorf("unexpected scope[1]: %+v", scopes[1])
	}
	if scopes[2].Name != "custom_scope" || scopes[2].Description != "custom_scope" {
		t.Errorf("unknown scopes should use name as description: %+v", scopes[2])
	}
}

func TestContainsPromptValue(t *testing.T) {
	tests := []struct {
		prompt string
		value  string
		want   bool
	}{
		{"consent", "consent", true},
		{"login consent", "consent", true},
		{"login", "consent", false},
		{"", "consent", false},
		{"consent login", "login", true},
	}
	for _, tt := range tests {
		if got := containsPromptValue(tt.prompt, tt.value); got != tt.want {
			t.Errorf("containsPromptValue(%q, %q) = %v, want %v", tt.prompt, tt.value, got, tt.want)
		}
	}
}
