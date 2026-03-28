package authui

// OAuthParams mirrors the TypeScript OAuthParams interface.
type OAuthParams struct {
	State               string `json:"state"`
	RedirectURI         string `json:"redirect_uri"`
	ClientID            string `json:"client_id"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

// ThemeData mirrors the TypeScript ThemeData interface.
type ThemeData struct {
	Title   string `json:"title"`
	LogoURL string `json:"logo_url"`
	CSS     string `json:"css"`
}

// FederatedProvider mirrors the TypeScript FederatedProvider interface.
type FederatedProvider struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	IconSVG string `json:"icon_svg"`
}

// LoginPageData mirrors LoginAuthData in the TypeScript types.
type LoginPageData struct {
	CsrfToken          string              `json:"csrf_token"`
	OAuth              OAuthParams         `json:"oauth"`
	OAuthPath          string              `json:"oauth_path"`
	Error              string              `json:"error"`
	AuthMode           string              `json:"auth_mode"`
	AllowSelfSignup    bool                `json:"allow_self_signup"`
	ProfileFieldEmail  string              `json:"profile_field_email"`
	FederatedProviders []FederatedProvider `json:"federated_providers"`
	Theme              ThemeData           `json:"theme"`
}

func (d LoginPageData) GetCsrfToken() string { return d.CsrfToken }

// SignupPageData mirrors SignupAuthData.
type SignupPageData struct {
	CsrfToken              string      `json:"csrf_token"`
	OAuth                  OAuthParams `json:"oauth"`
	OAuthPath              string      `json:"oauth_path"`
	Error                  string      `json:"error"`
	AuthMode               string      `json:"auth_mode"`
	ProfileFieldEmail      string      `json:"profile_field_email"`
	ProfileFieldGivenName  string      `json:"profile_field_given_name"`
	ProfileFieldFamilyName string      `json:"profile_field_family_name"`
	ProfileFieldPhone      string      `json:"profile_field_phone"`
	Theme                  ThemeData   `json:"theme"`
}

func (d SignupPageData) GetCsrfToken() string { return d.CsrfToken }

// MfaPageData mirrors MfaAuthData.
type MfaPageData struct {
	CsrfToken          string    `json:"csrf_token"`
	ChallengeID        string    `json:"challenge_id"`
	Method             string    `json:"method"`
	Error              string    `json:"error"`
	TrustDeviceEnabled bool      `json:"trust_device_enabled"`
	TrustDeviceDays    int       `json:"trust_device_days"`
	Theme              ThemeData `json:"theme"`
}

func (d MfaPageData) GetCsrfToken() string { return d.CsrfToken }

// MfaEnrollPageData mirrors MfaEnrollAuthData.
type MfaEnrollPageData struct {
	CsrfToken     string    `json:"csrf_token"`
	ChallengeID   string    `json:"challenge_id"`
	TotpSecret    string    `json:"totp_secret"`
	QRCodeDataURI string    `json:"qr_code_data_uri"`
	Error         string    `json:"error"`
	Theme         ThemeData `json:"theme"`
}

func (d MfaEnrollPageData) GetCsrfToken() string { return d.CsrfToken }

// VerifyEmailPageData mirrors VerifyEmailAuthData.
type VerifyEmailPageData struct {
	CsrfToken string      `json:"csrf_token"`
	OAuth     OAuthParams `json:"oauth"`
	OAuthPath string      `json:"oauth_path"`
	Mode      string      `json:"mode"`
	Username  string      `json:"username"`
	Error     string      `json:"error"`
	Theme     ThemeData   `json:"theme"`
}

func (d VerifyEmailPageData) GetCsrfToken() string { return d.CsrfToken }

// OnboardPageData mirrors OnboardAuthData.
type OnboardPageData struct {
	CsrfToken         string    `json:"csrf_token"`
	FormAction        string    `json:"form_action"`
	Error             string    `json:"error"`
	ProfileFieldEmail string    `json:"profile_field_email"`
	Theme             ThemeData `json:"theme"`
}

func (d OnboardPageData) GetCsrfToken() string { return d.CsrfToken }

// ErrorPageData has no CSRF token (error pages have no forms).
type ErrorPageData struct {
	Error string    `json:"error"`
	Theme ThemeData `json:"theme"`
}
