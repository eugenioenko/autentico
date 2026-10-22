package idpsession

import (
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/user"
	"github.com/stretchr/testify/require"
)

func TestSessionMfaEvidenceAgainstCurrentPolicy(t *testing.T) {
	for _, tt := range []struct {
		name, policy, evidence   string
		required, enrolled, want bool
	}{
		{"legacy without MFA", "totp", "", false, false, true},
		{"legacy cannot satisfy required MFA", "totp", "", true, false, false},
		{"legacy cannot bypass voluntary TOTP", "email", "", false, true, false},
		{"email cannot satisfy TOTP", "totp", "email", true, true, false},
		{"email cannot bypass voluntary TOTP", "email", "email", false, true, false},
		{"completed TOTP", "totp", "totp", true, true, true},
		{"completed email", "email", "email", true, false, true},
		{"both permits email fallback", "both", "email", true, true, true},
		{"both permits TOTP", "both", "totp", true, true, true},
		{"completed trusted-device SSO", "totp", "trusted_device", true, true, true},
		{"unknown evidence", "totp", "passkey", true, true, false},
		{"invalid MFA policy", "invalid", "totp", true, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			usr := &user.User{TotpVerified: tt.enrolled}
			cfg := &config.Config{RequireMfa: tt.required, MfaMethod: tt.policy}
			require.Equal(t, tt.want, SatisfiesMfa(tt.evidence, usr, cfg))
		})
	}
	deactivated := time.Now()
	require.False(t, SatisfiesMfa("totp", &user.User{DeactivatedAt: &deactivated}, &config.Config{}))
	require.False(t, SatisfiesMfa("totp", nil, &config.Config{}))
}
