package email

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// smtpProbe always joins its server before test fixtures are restored, including
// when a missing client deadline would otherwise leave either side blocked.
func smtpProbe(t *testing.T, serve func(net.Conn) error) (string, <-chan error, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan error, 1)
	var mu sync.Mutex
	var active net.Conn
	closing := false
	stop := func() {
		mu.Lock()
		closing = true
		if active != nil {
			_ = active.Close()
		}
		mu.Unlock()
		_ = listener.Close()
	}
	t.Cleanup(func() {
		stop()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("SMTP server did not stop")
		}
	})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer func() { _ = conn.Close() }()
		mu.Lock()
		active = conn
		stop := closing
		mu.Unlock()
		if stop {
			done <- nil
			return
		}
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			done <- err
			return
		}
		done <- serve(conn)
	}()
	return listener.Addr().String(), done, stop
}

func smtpCommand(tp *textproto.Conn, prefix string) error {
	line, err := tp.ReadLine()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("expected %s command", prefix)
	}
	return nil
}

func TestSMTPTimeoutReleasesStalledConnections(t *testing.T) {
	for _, stage := range []string{"greeting", "hello", "TLS handshake", "DATA acknowledgement", "QUIT"} {
		t.Run(stage, func(t *testing.T) {
			reached := make(chan struct{})
			addr, serverDone, stop := smtpProbe(t, func(conn net.Conn) error {
				stall := func() error { close(reached); _, err := io.Copy(io.Discard, conn); return err }
				if stage == "greeting" {
					return stall()
				}
				tp := textproto.NewConn(conn)
				if err := tp.PrintfLine("220 localhost test SMTP"); err != nil {
					return err
				}
				if err := smtpCommand(tp, "EHLO "); err != nil {
					return err
				}
				if stage == "hello" {
					return stall()
				}
				if stage == "TLS handshake" {
					if err := tp.PrintfLine("250-localhost\r\n250 STARTTLS"); err != nil {
						return err
					}
					if err := smtpCommand(tp, "STARTTLS"); err != nil {
						return err
					}
					if err := tp.PrintfLine("220 begin TLS"); err != nil {
						return err
					}
					return stall()
				}
				if err := tp.PrintfLine("250 localhost"); err != nil {
					return err
				}
				for _, command := range []string{"MAIL FROM:", "RCPT TO:"} {
					if err := smtpCommand(tp, command); err != nil {
						return err
					}
					if err := tp.PrintfLine("250 accepted"); err != nil {
						return err
					}
				}
				if err := smtpCommand(tp, "DATA"); err != nil {
					return err
				}
				if err := tp.PrintfLine("354 send data"); err != nil {
					return err
				}
				if _, err := io.ReadAll(tp.DotReader()); err != nil {
					return err
				}
				if stage == "DATA acknowledgement" {
					return stall()
				}
				if err := tp.PrintfLine("250 stored"); err != nil {
					return err
				}
				if err := smtpCommand(tp, "QUIT"); err != nil {
					return err
				}
				return stall()
			})
			result := make(chan error, 1)
			clientDone := make(chan struct{})
			t.Cleanup(func() {
				stop()
				select {
				case <-clientDone:
				case <-time.After(5 * time.Second):
					t.Error("SMTP client did not stop")
				}
			})
			go func() {
				defer close(clientDone)
				result <- sendMailWithTimeout(addr, nil, "from@example.test", []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n"), 200*time.Millisecond, nil)
			}()
			select {
			case <-reached:
			case <-time.After(2 * time.Second):
				t.Fatal("SMTP did not reach stalled stage")
			}
			select {
			case err := <-result:
				var timeout net.Error
				require.ErrorAs(t, err, &timeout)
				require.True(t, timeout.Timeout())
			case <-time.After(2 * time.Second):
				t.Fatal("SMTP deadline did not terminate delivery")
			}
			select {
			case err := <-serverDone:
				require.NoError(t, err, "the client must close its connection after timing out")
			case <-time.After(time.Second):
				t.Fatal("SMTP connection was left open")
			}
		})
	}
}

func smtpCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	require.NoError(t, err)
	parsed, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, roots
}

func TestSMTPPreservesDeliveryAuthAndCertificateValidation(t *testing.T) {
	for _, mode := range []string{"plain AUTH", "trusted STARTTLS AUTH", "untrusted STARTTLS", "HELO without auth", "AUTH unavailable"} {
		t.Run(mode, func(t *testing.T) {
			certificate, roots := smtpCertificate(t)
			received := make(chan string, 1)
			addr, serverDone, _ := smtpProbe(t, func(conn net.Conn) error {
				tp := textproto.NewConn(conn)
				if err := tp.PrintfLine("220 localhost test SMTP"); err != nil {
					return err
				}
				if err := smtpCommand(tp, "EHLO "); err != nil {
					return err
				}
				if strings.Contains(mode, "STARTTLS") {
					if err := tp.PrintfLine("250-localhost\r\n250 STARTTLS"); err != nil {
						return err
					}
					if err := smtpCommand(tp, "STARTTLS"); err != nil {
						return err
					}
					if err := tp.PrintfLine("220 begin TLS"); err != nil {
						return err
					}
					secure := tls.Server(conn, &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{certificate}})
					if err := secure.Handshake(); err != nil {
						if mode == "untrusted STARTTLS" {
							return nil
						}
						return err
					}
					tp = textproto.NewConn(secure)
					if err := smtpCommand(tp, "EHLO "); err != nil {
						return err
					}
				}
				switch mode {
				case "HELO without auth":
					if err := tp.PrintfLine("502 EHLO unsupported"); err != nil {
						return err
					}
					if err := smtpCommand(tp, "HELO "); err != nil {
						return err
					}
					if err := tp.PrintfLine("250 localhost"); err != nil {
						return err
					}
				case "AUTH unavailable":
					if err := tp.PrintfLine("250 localhost"); err != nil {
						return err
					}
					if _, err := tp.ReadLine(); err != io.EOF {
						return fmt.Errorf("unauthenticated SMTP command received")
					}
					return nil
				default:
					if err := tp.PrintfLine("250-localhost\r\n250 AUTH PLAIN"); err != nil {
						return err
					}
					expected := "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00user\x00password"))
					if err := smtpCommand(tp, expected); err != nil {
						return err
					}
					if err := tp.PrintfLine("235 authenticated"); err != nil {
						return err
					}
				}
				for _, command := range []string{"MAIL FROM:<from@example.test>", "RCPT TO:<to@example.test>"} {
					if err := smtpCommand(tp, command); err != nil {
						return err
					}
					if err := tp.PrintfLine("250 accepted"); err != nil {
						return err
					}
				}
				if err := smtpCommand(tp, "DATA"); err != nil {
					return err
				}
				if err := tp.PrintfLine("354 send data"); err != nil {
					return err
				}
				message, err := io.ReadAll(tp.DotReader())
				if err != nil {
					return err
				}
				received <- string(message)
				if err := tp.PrintfLine("250 stored"); err != nil {
					return err
				}
				if err := smtpCommand(tp, "QUIT"); err != nil {
					return err
				}
				return tp.PrintfLine("221 goodbye")
			})
			host, _, err := net.SplitHostPort(addr)
			require.NoError(t, err)
			auth := smtp.PlainAuth("", "user", "password", host)
			if mode == "HELO without auth" {
				auth = nil
			}
			var trustedRoots *x509.CertPool
			if mode == "trusted STARTTLS AUTH" {
				trustedRoots = roots
			}
			err = sendMailWithTimeout(addr, auth, "from@example.test", []string{"to@example.test"}, []byte("Subject: test\r\n\r\nbody\r\n.leading dot\r\n"), time.Second, trustedRoots)
			switch mode {
			case "untrusted STARTTLS":
				require.Error(t, err)
				var verification *tls.CertificateVerificationError
				require.True(t, errors.As(err, &verification), "certificate verification must remain enabled")
			case "AUTH unavailable":
				require.ErrorContains(t, err, "AUTH")
			default:
				require.NoError(t, err)
				select {
				case message := <-received:
					require.Contains(t, message, "body\n.leading dot\n")
				case <-time.After(time.Second):
					t.Fatal("SMTP message missing")
				}
			}
			select {
			case err := <-serverDone:
				require.NoError(t, err)
			case <-time.After(time.Second):
				t.Fatal("SMTP server did not complete")
			}
		})
	}
}

func TestSMTPRejectsInvalidInputsBeforeDialing(t *testing.T) {
	for _, tc := range []struct {
		name, from, to string
		timeout        time.Duration
		message        string
	}{
		{"disabled timeout", "from@example.test", "to@example.test", 0, "positive"},
		{"sender injection", "from@example.test\r\nINJECT", "to@example.test", time.Second, "newline"},
		{"recipient injection", "from@example.test", "to@example.test\nINJECT", time.Second, "newline"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := sendMailWithTimeout("not-an-address", nil, tc.from, []string{tc.to}, nil, tc.timeout, nil)
			require.ErrorContains(t, err, tc.message)
		})
	}
}
