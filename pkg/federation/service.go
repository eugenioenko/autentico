package federation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eugenioenko/autentico/pkg/config"
)

// SignState JSON-encodes the FederationState, signs it with HMAC-SHA256 using
// the CSRF secret, and returns a base64url-encoded "payload.signature" string.
func SignState(s FederationState) (string, error) {
	payload, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("failed to marshal federation state: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(payload)
	sig := computeHMAC(encoded)
	return encoded + "." + sig, nil
}

// VerifyState parses a signed state string produced by SignState, verifies the
// HMAC signature, and returns the decoded FederationState.
func VerifyState(raw string) (*FederationState, error) {
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid federation state format")
	}

	encoded, sig := parts[0], parts[1]
	expected := computeHMAC(encoded)
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, fmt.Errorf("federation state signature mismatch")
	}

	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decode federation state: %w", err)
	}

	var state FederationState
	if err := json.Unmarshal(payload, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal federation state: %w", err)
	}
	return &state, nil
}

func computeHMAC(data string) string {
	secret := []byte(config.GetBootstrap().AuthCSRFProtectionSecretKey)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
