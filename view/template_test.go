package view

import (
	"bytes"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/assert"
)

func TestParseTemplate(t *testing.T) {
	// Test parsing a few templates
	names := []string{"login", "signup", "error", "onboard"}
	for _, name := range names {
		tmpl, err := ParseTemplate(name)
		assert.NoError(t, err, "failed to parse template: %s", name)
		assert.NotNil(t, tmpl)
	}

	// Test invalid template
	_, err := ParseTemplate("nonexistent")
	assert.Error(t, err)
}

func TestTemplateHelpersExecution(t *testing.T) {
	config.Bootstrap.AppOAuthPath = "/custom-oauth"

	funcs := template.FuncMap{
		"authURL": func(path string) string {
			return config.GetBootstrap().AppOAuthPath + path
		},
	}

	t.Run("authURL", func(t *testing.T) {
		tHelper, err := template.New("test").Funcs(funcs).Parse(`{{authURL "/foo"}}`)
		assert.NoError(t, err)

		var buf bytes.Buffer
		err = tHelper.Execute(&buf, nil)
		assert.NoError(t, err)
		assert.Equal(t, "/custom-oauth/foo", buf.String())
	})
}

// TestHasThemeCssFunc covers the template func that gates the theme.css link.
func TestHasThemeCssFunc(t *testing.T) {
	prev := config.Values.ThemeCssResolved
	t.Cleanup(func() { config.Values.ThemeCssResolved = prev })

	tmpl, err := template.New("t").Funcs(template.FuncMap{
		"hasThemeCss": func() bool { return config.Get().ThemeCssResolved != "" },
	}).Parse(`{{if hasThemeCss}}yes{{else}}no{{end}}`)
	assert.NoError(t, err)

	var buf bytes.Buffer

	config.Values.ThemeCssResolved = "body{}"
	_ = tmpl.Execute(&buf, nil)
	assert.Equal(t, "yes", buf.String())

	config.Values.ThemeCssResolved = ""
	buf.Reset()
	_ = tmpl.Execute(&buf, nil)
	assert.Equal(t, "no", buf.String())
}

// TestLayoutThemeCSSRegression is the regression guard for issue #218. An admin
// who sets theme_css_inline must never be able to inject <script> or <style>
// tags into the rendered HTML — the resolved CSS is served as an external
// stylesheet, not inlined.
func TestLayoutThemeCSSRegression(t *testing.T) {
	prev := config.Values.ThemeCssResolved
	t.Cleanup(func() { config.Values.ThemeCssResolved = prev })

	config.Bootstrap.AppOAuthPath = "/oauth2"
	config.Values.ThemeCssResolved = `</style><script>alert(1)</script>body{color:red}`

	tmpl, err := ParseTemplate("error")
	assert.NoError(t, err)

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "layout", map[string]any{
		"ThemeTitle":   "T",
		"ThemeLogoUrl": "",
		"Error":        "boom",
	})
	assert.NoError(t, err)
	out := buf.String()

	// None of the admin-supplied CSS content must appear in the rendered HTML —
	// it's served separately at /oauth2/static/theme.css.
	assert.NotContains(t, out, "alert(1)", "admin CSS content must not be inlined into the page")
	assert.NotContains(t, out, "</style><script>", "the </style> breakout signature must never appear")
	assert.NotContains(t, out, "<style>", "rendered HTML must not inline theme CSS in a <style> block")
	assert.Contains(t, out, `href="/oauth2/static/theme.css"`, "theme CSS must be served as external stylesheet when set")
}

// TestLoginTemplateFederationIconRegression ensures federation provider SVGs
// are never injected inline — they're referenced via <img> tags, which neutralize
// embedded scripts per browser SVG-in-image rules.
func TestLoginTemplateFederationIconRegression(t *testing.T) {
	config.Bootstrap.AppOAuthPath = "/oauth2"

	tmpl, err := ParseTemplate("login")
	assert.NoError(t, err)

	type provider struct {
		ID      string
		Name    string
		HasIcon bool
	}

	var buf bytes.Buffer
	err = tmpl.ExecuteTemplate(&buf, "layout", map[string]any{
		"State":               "s",
		"RedirectURI":         "http://localhost/cb",
		"ClientID":            "c",
		"Scope":               "openid",
		"Nonce":               "n",
		"CodeChallenge":       "cc",
		"CodeChallengeMethod": "S256",
		"AuthorizeSig":        "sig",
		"Error":               "",
		"AuthMode":            "password",
		"AllowSelfSignup":     false,
		"SmtpConfigured":      false,
		"ProfileFieldEmail":   "optional",
		"ThemeTitle":          "T",
		"ThemeLogoUrl":        "",
		"FederatedProviders": []provider{
			{ID: "evil", Name: "Evil", HasIcon: true},
		},
	})
	assert.NoError(t, err)
	out := buf.String()

	// The page's own passkey block has a <script>; assert absence of federation
	// injection by checking for the <img> reference and scoping the <script>
	// check to the federation <a> element.
	assert.Contains(t, out, `src="/oauth2/federation/evil/icon.svg"`, "federation icon must be referenced via <img src>")
	// Everything between the federation button's opening <a> and its closing </a>
	// should be clean — no <script>, no raw SVG.
	idx := strings.Index(out, `/oauth2/federation/evil?`)
	assert.Greater(t, idx, 0, "federation anchor must appear in output")
	anchor := out[idx:]
	end := strings.Index(anchor, "</a>")
	assert.Greater(t, end, 0)
	anchor = anchor[:end]
	assert.NotContains(t, anchor, "<script", "federation button must not contain a <script> tag")
	assert.NotContains(t, anchor, "<svg", "federation button must not contain an inline <svg>")
}

func TestThemeCSSHandler(t *testing.T) {
	prev := config.Values.ThemeCssResolved
	t.Cleanup(func() { config.Values.ThemeCssResolved = prev })

	t.Run("serves resolved css with etag", func(t *testing.T) {
		config.Values.ThemeCssResolved = "body{color:red}"
		req := httptest.NewRequest(http.MethodGet, "/oauth2/static/theme.css", nil)
		rr := httptest.NewRecorder()
		ThemeCSSHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
		assert.NotEmpty(t, rr.Header().Get("ETag"))
		assert.Equal(t, "body{color:red}", rr.Body.String())
	})

	t.Run("empty css still returns 200 with text/css", func(t *testing.T) {
		config.Values.ThemeCssResolved = ""
		req := httptest.NewRequest(http.MethodGet, "/oauth2/static/theme.css", nil)
		rr := httptest.NewRecorder()
		ThemeCSSHandler().ServeHTTP(rr, req)

		assert.Equal(t, http.StatusOK, rr.Code)
		assert.Equal(t, "text/css; charset=utf-8", rr.Header().Get("Content-Type"))
		assert.Empty(t, rr.Body.String())
	})

	t.Run("304 on matching If-None-Match", func(t *testing.T) {
		config.Values.ThemeCssResolved = "body{}"
		req := httptest.NewRequest(http.MethodGet, "/oauth2/static/theme.css", nil)
		rr := httptest.NewRecorder()
		ThemeCSSHandler().ServeHTTP(rr, req)
		etag := rr.Header().Get("ETag")

		req2 := httptest.NewRequest(http.MethodGet, "/oauth2/static/theme.css", nil)
		req2.Header.Set("If-None-Match", etag)
		rr2 := httptest.NewRecorder()
		ThemeCSSHandler().ServeHTTP(rr2, req2)
		assert.Equal(t, http.StatusNotModified, rr2.Code)
		assert.Empty(t, rr2.Body.String())
	})
}
