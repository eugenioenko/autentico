package idpsession

import (
	"math"
	"testing"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestSessionFreshnessLimitsAndMaxAgeOverflow(t *testing.T) {
	now := time.Now().UTC()
	session := &IdpSession{CreatedAt: now.Add(-time.Hour), LastActivityAt: now.Add(-10 * time.Second)}
	cfg := &config.Config{AuthSsoSessionIdleTimeout: time.Minute, AuthSsoSessionMaxAge: 2 * time.Hour}
	require.True(t, IsFresh(session, cfg, now))
	require.True(t, WithinMaxAge(session, math.MaxInt64, now))
	require.False(t, WithinMaxAge(session, 0, now))
	require.False(t, WithinMaxAge(session, 60, now))
	require.True(t, WithinMaxAge(session, -1, now))
	session.LastActivityAt = now.Add(-time.Minute)
	require.False(t, IsFresh(session, cfg, now), "idle deadline is exclusive")
	cfg.AuthSsoSessionIdleTimeout = 0
	require.True(t, IsFresh(session, cfg, now), "zero disables the idle limit")
	session.CreatedAt = now.Add(-2 * time.Hour)
	require.False(t, IsFresh(session, cfg, now), "absolute age still applies")
	cfg.AuthSsoSessionMaxAge = 0
	require.True(t, IsFresh(session, cfg, now))
	session.CreatedAt = now.Add(time.Second)
	require.False(t, IsFresh(session, cfg, now))
}
