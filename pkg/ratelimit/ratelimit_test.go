package ratelimit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// newStore is a helper that creates a Store with default two-tier limits.
func newStore(rps float64, burst int, rpm float64, burstPerMin int) *Store {
	return NewStore(rps, burst, rpm, burstPerMin)
}

func TestAllow_WithinBurst(t *testing.T) {
	s := newStore(5, 10, 20, 20)
	// All burst requests should be allowed immediately (per-second burst=10, per-minute burst=20)
	for i := 0; i < 10; i++ {
		assert.True(t, s.Allow("1.2.3.4"), "request %d should be allowed within burst", i+1)
	}
}

func TestAllow_ExceedsPerSecondBurst(t *testing.T) {
	s := newStore(5, 3, 100, 100) // per-second burst=3, per-minute generous
	s.Allow("1.2.3.4")
	s.Allow("1.2.3.4")
	s.Allow("1.2.3.4")
	// Per-second burst exhausted
	assert.False(t, s.Allow("1.2.3.4"))
}

func TestAllow_ExceedsPerMinuteBurst(t *testing.T) {
	s := newStore(100, 100, 5, 3) // per-second generous, per-minute burst=3
	s.Allow("1.2.3.4")
	s.Allow("1.2.3.4")
	s.Allow("1.2.3.4")
	// Per-minute burst exhausted
	assert.False(t, s.Allow("1.2.3.4"))
}

func TestAllow_DifferentIPsAreIndependent(t *testing.T) {
	s := newStore(5, 2, 20, 2)
	// Exhaust IP A on both tiers
	s.Allow("1.1.1.1")
	s.Allow("1.1.1.1")
	assert.False(t, s.Allow("1.1.1.1"))

	// IP B should still have its full burst
	assert.True(t, s.Allow("2.2.2.2"))
}

func TestAllow_DisabledStore(t *testing.T) {
	s := newStore(0, 10, 20, 20)
	for i := 0; i < 100; i++ {
		assert.True(t, s.Allow("1.2.3.4"), "disabled store should always allow")
	}
}

func TestAllow_NegativeRPS(t *testing.T) {
	s := newStore(-1, 10, 20, 20)
	assert.True(t, s.Allow("1.2.3.4"))
}

func TestCleanup_RemovesStaleEntries(t *testing.T) {
	s := newStore(5, 10, 20, 20)
	s.Allow("1.2.3.4")

	// Back-date the entry so it looks stale
	s.mu.Lock()
	s.limiters["1.2.3.4"].lastSeen = time.Now().Add(-11 * time.Minute)
	s.mu.Unlock()

	s.Cleanup(10 * time.Minute)

	s.mu.Lock()
	_, exists := s.limiters["1.2.3.4"]
	s.mu.Unlock()

	assert.False(t, exists, "stale entry should have been evicted")
}

func TestCleanup_KeepsRecentEntries(t *testing.T) {
	s := newStore(5, 10, 20, 20)
	s.Allow("1.2.3.4")

	s.Cleanup(10 * time.Minute)

	s.mu.Lock()
	_, exists := s.limiters["1.2.3.4"]
	s.mu.Unlock()

	assert.True(t, exists, "recent entry should be kept")
}

func TestCleanup_OnlyEvictsStale(t *testing.T) {
	s := newStore(5, 10, 20, 20)
	s.Allow("stale.ip")
	s.Allow("fresh.ip")

	s.mu.Lock()
	s.limiters["stale.ip"].lastSeen = time.Now().Add(-11 * time.Minute)
	s.mu.Unlock()

	s.Cleanup(10 * time.Minute)

	s.mu.Lock()
	_, staleExists := s.limiters["stale.ip"]
	_, freshExists := s.limiters["fresh.ip"]
	s.mu.Unlock()

	assert.False(t, staleExists)
	assert.True(t, freshExists)
}
