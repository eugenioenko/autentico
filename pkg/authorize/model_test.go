package authorize

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateAuthorizeRequest_ValidScopes(t *testing.T) {
	base := AuthorizeRequest{
		ResponseType: "code",
		RedirectURI:  "http://localhost/callback",
	}

	// Standard OIDC scopes should pass validation
	tests := []struct {
		name  string
		scope string
	}{
		{"openid only", "openid"},
		{"openid profile", "openid profile"},
		{"openid profile email", "openid profile email"},
		{"all standard OIDC scopes", "openid profile email address phone offline_access"},
		{"custom scope", "custom_scope"},
		{"mixed scopes", "openid custom:read custom:write"},
		{"empty scope", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.Scope = tt.scope
			err := ValidateAuthorizeRequest(req)
			assert.NoError(t, err, "scope %q should be valid", tt.scope)
		})
	}
}

func TestValidateAuthorizeRequest_InvalidScopeSyntax(t *testing.T) {
	base := AuthorizeRequest{
		ResponseType: "code",
		RedirectURI:  "http://localhost/callback",
	}

	// RFC 6749 §3.3: scope tokens must be NQCHAR (%x21 / %x23-5B / %x5D-7E)
	tests := []struct {
		name  string
		scope string
	}{
		{"contains backslash", `openid profile\bad`},
		{"contains double-quote", `openid "profile"`},
		{"contains control character", "openid \x01bad"},
		{"contains non-ASCII", "openid prof\xc3\xadle"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := base
			req.Scope = tt.scope
			err := ValidateAuthorizeRequest(req)
			assert.Error(t, err, "scope %q should be invalid", tt.scope)
		})
	}
}

func TestValidateScopeSyntax_Unit(t *testing.T) {
	// Valid tokens
	assert.NoError(t, validateScopeSyntax("openid"))
	assert.NoError(t, validateScopeSyntax("openid profile email"))
	assert.NoError(t, validateScopeSyntax("a:b:c"))
	assert.NoError(t, validateScopeSyntax("scope-with-dash"))
	assert.NoError(t, validateScopeSyntax("scope_with_underscore"))
	assert.NoError(t, validateScopeSyntax("scope.with.dots"))
	assert.NoError(t, validateScopeSyntax(""))

	// All printable ASCII except space, double-quote, backslash
	assert.NoError(t, validateScopeSyntax("!#$%&'()*+,-./0123456789"))
	assert.NoError(t, validateScopeSyntax(":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ["))
	assert.NoError(t, validateScopeSyntax("]^_`abcdefghijklmnopqrstuvwxyz{|}~"))

	// Invalid tokens
	assert.Error(t, validateScopeSyntax(`has\"quote`))
	assert.Error(t, validateScopeSyntax(`has\backslash`))
	assert.Error(t, validateScopeSyntax("has\x00null"))
	assert.Error(t, validateScopeSyntax("has\x1fcontrol"))
}

func TestValidateScopeToken_Unit(t *testing.T) {
	// Valid
	assert.NoError(t, validateScopeToken("openid"))
	assert.NoError(t, validateScopeToken("profile"))
	assert.NoError(t, validateScopeToken("a:b"))
	assert.NoError(t, validateScopeToken("!#$%"))

	// Invalid: double-quote (0x22)
	assert.Error(t, validateScopeToken(`"`))
	// Invalid: backslash (0x5C)
	assert.Error(t, validateScopeToken(`\`))
	// Invalid: space (0x20) - though normally split by Fields()
	assert.Error(t, validateScopeToken(" "))
	// Invalid: DEL (0x7F)
	assert.Error(t, validateScopeToken("\x7f"))
	// Invalid: non-ASCII
	assert.Error(t, validateScopeToken("\x80"))
}

func TestValidateAuthorizeRequest_SubsetOfClientScopes(t *testing.T) {
	// Structural validation at the model level accepts any valid scope syntax.
	// Per-client scope restriction is handled by client.ValidateScopes in the handler.
	// This test verifies that a subset of well-formed scopes passes model validation.
	req := AuthorizeRequest{
		ResponseType: "code",
		RedirectURI:  "http://localhost/callback",
		Scope:        "openid",
	}
	assert.NoError(t, ValidateAuthorizeRequest(req))

	req.Scope = "openid profile"
	assert.NoError(t, ValidateAuthorizeRequest(req))
}

func TestValidateAuthorizeRequest_MissingResponseType(t *testing.T) {
	req := AuthorizeRequest{
		RedirectURI: "http://localhost/callback",
		Scope:       "openid",
	}
	err := ValidateAuthorizeRequest(req)
	assert.Error(t, err, "missing response_type should fail validation")
}

func TestValidateAuthorizeRequest_MissingRedirectURI(t *testing.T) {
	req := AuthorizeRequest{
		ResponseType: "code",
		Scope:        "openid",
	}
	err := ValidateAuthorizeRequest(req)
	assert.Error(t, err, "missing redirect_uri should fail validation")
}
