package email

import (
	"testing"
)

func TestSmtpEnvelopeFrom_DisplayName(t *testing.T) {
	header, envelope, err := smtpEnvelopeFrom(`Little Village <no-reply@lvlc.test>`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if envelope != "no-reply@lvlc.test" {
		t.Fatalf("envelope = %q, want bare address", envelope)
	}
	if header == "" || header == envelope {
		t.Fatalf("header = %q, want display-name form", header)
	}
}

func TestSmtpEnvelopeFrom_BareAddress(t *testing.T) {
	header, envelope, err := smtpEnvelopeFrom("no-reply@example.test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if envelope != "no-reply@example.test" {
		t.Fatalf("envelope = %q", envelope)
	}
	if header == "" {
		t.Fatal("header empty")
	}
}

func TestSmtpEnvelopeFrom_Empty(t *testing.T) {
	_, _, err := smtpEnvelopeFrom("   ")
	if err == nil {
		t.Fatal("expected error for empty smtp_from")
	}
}
