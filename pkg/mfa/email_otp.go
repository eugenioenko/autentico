package mfa

import (
	"crypto/rand"
	"fmt"
	"html/template"
	"math/big"
)

func GenerateEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func SendTestEmail(to string) error {
	body := template.HTML(`<p style="margin:0;color:#52525b;">Your SMTP configuration is working correctly. Emails will be delivered successfully.</p>`)
	return sendEmail(to, "SMTP Test", "Your SMTP configuration is working.", body)
}

func SendVerificationEmail(to, verifyURL string) error {
	body := template.HTML(fmt.Sprintf(`
<p style="margin:0 0 32px 0;color:#52525b;">Click the button below to verify your email address and complete your registration.</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 32px 0;">
  <tr>
    <td style="background-color:#18181b;border-radius:8px;padding:0;">
      <a href="%s" style="display:inline-block;padding:14px 32px;font-size:15px;font-weight:600;color:#ffffff;text-decoration:none;letter-spacing:-0.1px;">Verify my email</a>
    </td>
  </tr>
</table>
<p style="margin:0;font-size:13px;color:#a1a1aa;">This link expires in 24 hours. If you did not create an account, no action is required.</p>`,
		verifyURL,
	))
	return sendEmail(to, "Verify your email address", "Verify your email to complete your registration.", body)
}

func SendEmailOTP(to, code string) error {
	body := template.HTML(fmt.Sprintf(`
<p style="margin:0 0 32px 0;color:#52525b;">Use the code below to complete your sign-in. It expires in <strong>5 minutes</strong>.</p>
<table role="presentation" cellpadding="0" cellspacing="0" style="margin:0 0 32px 0;">
  <tr>
    <td style="background-color:#f4f4f5;border-radius:8px;padding:20px 40px;">
      <span style="font-size:36px;font-weight:700;letter-spacing:10px;color:#18181b;font-family:'Courier New',Courier,monospace;">%s</span>
    </td>
  </tr>
</table>
<p style="margin:0;font-size:13px;color:#a1a1aa;">Do not share this code with anyone.</p>`,
		code,
	))
	return sendEmail(to, "Your verification code", "Your sign-in verification code — expires in 5 minutes.", body)
}
