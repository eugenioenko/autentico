package authzsig

import (
	"net/url"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
)

func TestFromValuesPreservesSignedFields(t *testing.T) {
	p := AuthorizeParams{ClientID: "client", RedirectURI: "https://rp.example/cb?kept=a%2Bb",
		Scope: "openid email", Nonce: "nonce + é", State: "state&code=injected#fragment",
		CodeChallenge: "challenge", CodeChallengeMethod: "S256", Prompt: "login consent", MaxAge: "30"}
	v := url.Values{"client_id": {p.ClientID}, "redirect_uri": {p.RedirectURI}, "scope": {p.Scope},
		"nonce": {p.Nonce}, "state": {p.State}, "code_challenge": {p.CodeChallenge}, "code_challenge_method": {p.CodeChallengeMethod}, "prompt": {p.Prompt}, "max_age": {p.MaxAge}}
	decoded, err := url.ParseQuery(v.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if got := FromValues(decoded); got != p {
		t.Fatalf("signed values changed: %+v", got)
	}
	if got := FromValues(nil); got != (AuthorizeParams{}) {
		t.Fatalf("missing values gained defaults: %+v", got)
	}
}

func init() {
	if err := config.InitBootstrap(); err != nil {
		panic(err)
	}
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

func TestAuthenticationControlsCannotBeRemovedOrRelaxed(t *testing.T) {
	original := AuthorizeParams{ClientID: "client", RedirectURI: "https://rp.example/cb", Scope: "openid", State: "state", Prompt: "login consent", MaxAge: "30"}
	signature := Sign(original)
	for _, changed := range []AuthorizeParams{
		func() AuthorizeParams { p := original; p.Prompt = ""; return p }(),
		func() AuthorizeParams { p := original; p.Prompt = "consent"; return p }(),
		func() AuthorizeParams { p := original; p.MaxAge = ""; return p }(),
		func() AuthorizeParams { p := original; p.MaxAge = "300"; return p }(),
		func() AuthorizeParams { p := original; p.MaxAge = ""; p.Prompt = ""; return p }(),
	} {
		if Verify(changed, signature) {
			t.Fatalf("accepted changed controls: %+v", changed)
		}
	}
	if !Verify(original, signature) {
		t.Fatal("rejected unchanged controls")
	}
}

func TestOrdinaryPendingLinksKeepLegacySignatures(t *testing.T) {
	p := AuthorizeParams{ClientID: "client", RedirectURI: "https://rp.example/cb", Scope: "openid", Nonce: "nonce", CodeChallenge: "challenge", CodeChallengeMethod: "S256", State: "state"}
	if got := canonicalize(p); got != "client\nhttps://rp.example/cb\nopenid\nnonce\nchallenge\nS256\nstate" {
		t.Fatalf("ordinary pending link changed canonicalization: %q", got)
	}
	signature := Sign(p)
	p.MaxAge = "0"
	if Verify(p, signature) {
		t.Fatal("legacy signature accepted injected freshness control")
	}
}
