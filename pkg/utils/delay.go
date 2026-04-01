package utils

import (
	"crypto/rand"
	"math/big"
	"time"
)

// Anti-timing constants used to prevent user enumeration via response time.
const (
	AntiTimingMinMs = 50
	AntiTimingMaxMs = 200
)

// RandomDelay sleeps for a random duration between AntiTimingMinMs and
// AntiTimingMaxMs milliseconds. Used to prevent timing-based user enumeration.
func RandomDelay() {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(AntiTimingMaxMs-AntiTimingMinMs)))
	time.Sleep(time.Duration(int64(AntiTimingMinMs)+n.Int64()) * time.Millisecond)
}
