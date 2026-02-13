package mfa

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net/smtp"

	"github.com/eugenioenko/autentico/pkg/config"
)

func GenerateEmailOTP() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func SendEmailOTP(to, code string) error {
	cfg := config.Get()
	if cfg.SmtpHost == "" {
		return fmt.Errorf("SMTP is not configured")
	}

	from := cfg.SmtpFrom
	subject := "Your verification code"
	body := fmt.Sprintf("Your verification code is: %s\n\nThis code expires in 5 minutes.", code)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
		from, to, subject, body)

	addr := fmt.Sprintf("%s:%s", cfg.SmtpHost, cfg.SmtpPort)

	var auth smtp.Auth
	if cfg.SmtpUsername != "" {
		auth = smtp.PlainAuth("", cfg.SmtpUsername, cfg.SmtpPassword, cfg.SmtpHost)
	}

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}
