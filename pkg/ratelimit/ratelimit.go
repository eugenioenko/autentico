package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Store is an in-memory, per-IP two-tier rate limiter.
// Each IP gets a short-term (per-second) and a long-term (per-minute) token
// bucket. A request must pass both to be allowed. Entries are evicted by
// Cleanup after being idle for a configurable duration.
type Store struct {
	mu         sync.Mutex
	limiters   map[string]*entry
	rps        rate.Limit
	burst      int
	rpm        rate.Limit
	burstPerMin int
}

type entry struct {
	perSecond *rate.Limiter
	perMinute *rate.Limiter
	lastSeen  time.Time
}

// NewStore creates a Store with a per-second and per-minute limit.
// Pass rps <= 0 to disable rate limiting entirely (Allow always returns true).
func NewStore(rps float64, burst int, rpm float64, burstPerMin int) *Store {
	return &Store{
		limiters:    make(map[string]*entry),
		rps:         rate.Limit(rps),
		burst:       burst,
		rpm:         rate.Limit(rpm / 60.0),
		burstPerMin: burstPerMin,
	}
}

// Allow reports whether the given IP is within both rate limits.
func (s *Store) Allow(ip string) bool {
	if s.rps <= 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.limiters[ip]
	if !ok {
		e = &entry{
			perSecond: rate.NewLimiter(s.rps, s.burst),
			perMinute: rate.NewLimiter(s.rpm, s.burstPerMin),
		}
		s.limiters[ip] = e
	}
	e.lastSeen = time.Now()
	return e.perSecond.Allow() && e.perMinute.Allow()
}

// Cleanup removes entries that have not been seen within maxAge.
// Call this periodically to prevent unbounded memory growth.
func (s *Store) Cleanup(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	threshold := time.Now().Add(-maxAge)
	for ip, e := range s.limiters {
		if e.lastSeen.Before(threshold) {
			delete(s.limiters, ip)
		}
	}
}
