package email

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/smtp"
	"strings"
	"time"
)

const smtpOperationTimeout = 30 * time.Second

// sendMailWithTimeout follows net/smtp.SendMail's STARTTLS and envelope flow,
// with bounded connection setup and per-command I/O (RFC 5321 §4.5.3.2).
// Optional roots support isolated certificate tests; production uses
// system roots and always verifies the configured SMTP host.
func sendMailWithTimeout(addr string, auth smtp.Auth, from string, to []string, message []byte, timeout time.Duration, roots *x509.CertPool) error {
	// RFC 5321 §4.5.3.2: timeout protection cannot be disabled.
	if timeout <= 0 {
		return errors.New("smtp: timeout must be positive")
	}
	// RFC 5321 §4.1.2: command arguments cannot inject another SMTP line.
	for _, address := range append([]string{from}, to...) {
		if strings.ContainsAny(address, "\r\n") {
			return errors.New("smtp: address contains a newline")
		}
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	operation := func(run func() error) error {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return err
		}
		return run()
	}
	// RFC 5321 §3.1 / §4.1.1.1: greeting and EHLO (or HELO fallback).
	var client *smtp.Client
	if err := operation(func() error { client, err = smtp.NewClient(conn, host); return err }); err != nil {
		return err
	}
	defer func() { _ = client.Close() }()
	if err := operation(func() error { return client.Hello("localhost") }); err != nil {
		return err
	}
	// RFC 3207 §4–4.2: verify the peer and refresh EHLO capabilities after TLS.
	if supported, _ := client.Extension("STARTTLS"); supported {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, RootCAs: roots}
		if err := operation(func() error { return client.StartTLS(cfg) }); err != nil {
			return err
		}
	}
	// RFC 4954 §4: configured authentication must succeed before the envelope.
	if auth != nil {
		if supported, _ := client.Extension("AUTH"); !supported {
			return errors.New("smtp: server does not support AUTH")
		}
		if err := operation(func() error { return client.Auth(auth) }); err != nil {
			return err
		}
	}
	// RFC 5321 §4.1.1.2–4: send the envelope and complete the DATA transaction.
	if err := operation(func() error { return client.Mail(from) }); err != nil {
		return err
	}
	for _, recipient := range to {
		if err := operation(func() error { return client.Rcpt(recipient) }); err != nil {
			return err
		}
	}
	var writer io.WriteCloser
	if err := operation(func() error { writer, err = client.Data(); return err }); err != nil {
		return err
	}
	if err := operation(func() error { _, err := writer.Write(message); return err }); err != nil {
		return err
	}
	if err := operation(writer.Close); err != nil {
		return err
	}
	// RFC 5321 §4.1.1.10: a stalled QUIT reply also has a finite deadline.
	return operation(client.Quit)
}
