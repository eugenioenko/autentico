package email

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"

	"github.com/eugenioenko/autentico/pkg/config"
)

//go:embed email_body_test.html
var bodyTestRaw string

//go:embed email_body_verify.html
var bodyVerifyRaw string

//go:embed email_body_reset.html
var bodyResetRaw string

//go:embed email_body_otp.html
var bodyOTPRaw string

var (
	bodyTestTmpl   = template.Must(template.New("body_test").Parse(bodyTestRaw))
	bodyVerifyTmpl = template.Must(template.New("body_verify").Parse(bodyVerifyRaw))
	bodyResetTmpl  = template.Must(template.New("body_reset").Parse(bodyResetRaw))
	bodyOTPTmpl    = template.Must(template.New("body_otp").Parse(bodyOTPRaw))
)

func brandColor() string {
	c := config.Get().Theme.BrandColor
	if c == "" {
		return "#18181b"
	}
	return c
}

func adminURL() string {
	return config.GetBootstrap().AppURL + "/admin"
}

func renderBody(tmpl *template.Template, data any) (template.HTML, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return template.HTML(buf.String()), nil
}

func SendTestEmail(to string) error {
	body, err := renderBody(bodyTestTmpl, struct {
		BrandColor string
		AdminURL   string
	}{brandColor(), adminURL()})
	if err != nil {
		return fmt.Errorf("failed to render email body: %w", err)
	}
	return SendEmail(to, "SMTP Test", "Your SMTP configuration is working.", body)
}

func SendVerificationEmail(to, verifyURL string) error {
	body, err := renderBody(bodyVerifyTmpl, struct {
		BrandColor string
		VerifyURL  string
	}{brandColor(), verifyURL})
	if err != nil {
		return fmt.Errorf("failed to render email body: %w", err)
	}
	return SendEmail(to, "Verify your email address", "Verify your email to complete your registration.", body)
}

func SendPasswordResetEmail(to, resetURL string) error {
	body, err := renderBody(bodyResetTmpl, struct {
		BrandColor string
		ResetURL   string
	}{brandColor(), resetURL})
	if err != nil {
		return fmt.Errorf("failed to render email body: %w", err)
	}
	return SendEmail(to, "Reset your password", "Reset your password — this link expires in 1 hour.", body)
}

func SendEmailOTP(to, code string) error {
	body, err := renderBody(bodyOTPTmpl, struct {
		Code string
	}{code})
	if err != nil {
		return fmt.Errorf("failed to render email body: %w", err)
	}
	return SendEmail(to, "Your verification code", "Your sign-in verification code — expires in 5 minutes.", body)
}
