package authzsig

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
)

func init() {
	config.InitBootstrap()
}

func TestSignAndVerify(t *testing.T) {
	p := AuthorizeParams{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid profile email",
		Nonce:               "abc123",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "test-state",
	}

	sig := Sign(p)
	if sig == "" {
		t.Fatal("Sign returned empty string")
	}
	if !Verify(p, sig) {
		t.Fatal("Verify returned false for valid signature")
	}
}

func TestVerify_TamperedScope(t *testing.T) {
	p := AuthorizeParams{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		Nonce:               "",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "test-state",
	}

	sig := Sign(p)

	// Tamper with scope
	p.Scope = "openid profile email offline_access"
	if Verify(p, sig) {
		t.Fatal("Verify should reject tampered scope")
	}
}

func TestVerify_TamperedPKCE(t *testing.T) {
	p := AuthorizeParams{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		Nonce:               "",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		State:               "test-state",
	}

	sig := Sign(p)

	// Strip PKCE
	p.CodeChallenge = ""
	p.CodeChallengeMethod = ""
	if Verify(p, sig) {
		t.Fatal("Verify should reject stripped PKCE")
	}
}

func TestVerify_TamperedNonce(t *testing.T) {
	p := AuthorizeParams{
		ClientID:            "test-client",
		RedirectURI:         "http://localhost/callback",
		Scope:               "openid",
		Nonce:               "",
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		State:               "test-state",
	}

	sig := Sign(p)

	// Inject nonce
	p.Nonce = "attacker-injected-nonce"
	if Verify(p, sig) {
		t.Fatal("Verify should reject injected nonce")
	}
}

func TestVerify_WrongSignature(t *testing.T) {
	p := AuthorizeParams{
		ClientID: "test-client",
		Scope:    "openid",
		State:    "test-state",
	}

	if Verify(p, "invalid-signature") {
		t.Fatal("Verify should reject invalid signature")
	}
}

func TestVerify_EmptyParams(t *testing.T) {
	p := AuthorizeParams{}
	sig := Sign(p)
	if !Verify(p, sig) {
		t.Fatal("Verify should accept valid signature for empty params")
	}
}
