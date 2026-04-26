package email

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"net/smtp"
	"net/url"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
)

//go:embed email.html
var emailTemplateRaw string

var emailTemplate = template.Must(template.New("email").Parse(emailTemplateRaw))

type emailData struct {
	AppName         string
	LogoURL         string
	Tagline         string
	AccountURL      string
	Title           string
	Preheader       string
	BrandColor      string
	Body            template.HTML
	FooterLinks     []config.FooterLink
	FooterTextLines []string
}

func buildEmailHTML(title, preheader string, bodyHTML template.HTML) (string, error) {
	cfg := config.Get()
	bs := config.GetBootstrap()

	appName := cfg.Theme.Title
	if appName == "" {
		appName = "Autentico"
	}

	logoURL := cfg.Theme.LogoUrl
	if logoURL == "" {
		logoURL = bs.AppURL + "/oauth2/static/logo.svg"
	}

	brandColor := cfg.Theme.BrandColor
	if brandColor == "" {
		brandColor = "#18181b"
	}

	var footerTextLines []string
	if cfg.Theme.EmailFooterText != "" {
		footerTextLines = strings.Split(cfg.Theme.EmailFooterText, "\n")
	}

	var safeLinks []config.FooterLink
	for _, link := range cfg.FooterLinks {
		if u, err := url.Parse(link.URL); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			safeLinks = append(safeLinks, link)
		}
	}

	data := emailData{
		AppName:         appName,
		LogoURL:         logoURL,
		Tagline:         cfg.Theme.Tagline,
		AccountURL:      bs.AppURL + "/account",
		Title:           title,
		Preheader:       preheader,
		BrandColor:      brandColor,
		Body:            bodyHTML,
		FooterLinks:     safeLinks,
		FooterTextLines: footerTextLines,
	}

	var buf bytes.Buffer
	if err := emailTemplate.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func SendEmail(to, subject, preheader string, bodyHTML template.HTML) error {
	cfg := config.Get()
	if cfg.SmtpHost == "" {
		return fmt.Errorf("SMTP is not configured")
	}

	htmlContent, err := buildEmailHTML(subject, preheader, bodyHTML)
	if err != nil {
		return fmt.Errorf("failed to build email: %w", err)
	}

	from := cfg.SmtpFrom
	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=\"utf-8\"\r\n\r\n%s",
		from, to, subject, htmlContent,
	)

	addr := fmt.Sprintf("%s:%s", cfg.SmtpHost, cfg.SmtpPort)

	var auth smtp.Auth
	if cfg.SmtpUsername != "" {
		auth = smtp.PlainAuth("", cfg.SmtpUsername, cfg.SmtpPassword, cfg.SmtpHost)
	}

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}
