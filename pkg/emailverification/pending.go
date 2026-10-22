package emailverification

import (
	"net/http"
	"net/url"
	"time"

	"github.com/eugenioenko/autentico/pkg/authzsig"
	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/email"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/eugenioenko/autentico/view"
)

func signVerifiedParams(p OAuthParams) (OAuthParams, error) {
	params := authzsig.AuthorizeParams{
		ClientID: p.ClientID, RedirectURI: p.RedirectURI, Scope: p.Scope, State: p.State,
		Nonce: p.Nonce, CodeChallenge: p.CodeChallenge, CodeChallengeMethod: p.CodeChallengeMethod,
		Prompt: p.Prompt,
		MaxAge: p.MaxAge,
	}
	// RFC 6749 §10.6: validate the registered callback before issuing a signature.
	if _, err := client.ValidateAuthorization(params); err != nil {
		return p, err
	}
	p.AuthorizeSig = authzsig.Sign(params)
	return p, nil
}

// PendingURL resumes verification in the browser without exposing a verification
// token to that browser. Only the email delivery contains the bearer token.
func PendingURL(username string, p OAuthParams) (string, error) {
	p, err := signVerifiedParams(p)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(BuildVerifyURL("", p))
	if err != nil {
		return "", err
	}
	u.Path += "/pending"
	q := u.Query()
	q.Del("token")
	q.Set("username", username)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// SendVerification sends the existing verification flow after a passkey signup.
func SendVerification(usr *user.User, p OAuthParams) error {
	p, err := signVerifiedParams(p)
	if err != nil {
		return err
	}
	raw, hash, err := GenerateToken()
	if err != nil {
		return err
	}
	if err := user.SetEmailVerificationToken(usr.ID, hash, time.Now().Add(config.Get().EmailVerificationExpiration)); err != nil {
		return err
	}
	return email.SendVerificationEmail(usr.Email, BuildVerifyURL(raw, p))
}

// HandlePendingVerification displays the existing resend form. It deliberately
// does not look up the username, so it reveals no account or verification state.
func HandlePendingVerification(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	params := authzsig.FromValues(q)
	// RFC 6749 §10.6: the pending page must not sign or resume arbitrary callbacks.
	if !authzsig.Verify(params, q.Get("authorize_sig")) {
		view.RenderError(w, r, http.StatusBadRequest, "Invalid authorization request")
		return
	}
	if _, err := client.ValidateAuthorization(params); err != nil {
		view.RenderError(w, r, http.StatusBadRequest, err.Error())
		return
	}
	RenderVerifyEmail(w, r, "blocked", q.Get("username"), OAuthParams{
		ClientID: params.ClientID, RedirectURI: params.RedirectURI, Scope: params.Scope, State: params.State,
		Nonce: params.Nonce, CodeChallenge: params.CodeChallenge, CodeChallengeMethod: params.CodeChallengeMethod,
		AuthorizeSig: q.Get("authorize_sig"),
		Prompt:       params.Prompt,
		MaxAge:       params.MaxAge,
	}, "")
}
