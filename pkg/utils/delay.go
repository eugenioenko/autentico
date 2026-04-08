package utils

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
)

// RandomDelay sleeps for a random duration between AntiTimingMinMs and
// AntiTimingMaxMs (bootstrap config) to prevent timing-based user enumeration.
// Both values set to 0 disables the delay.
func RandomDelay() {
	bs := config.GetBootstrap()
	minMs := bs.AntiTimingMinMs
	maxMs := bs.AntiTimingMaxMs
	if maxMs <= minMs {
		return
	}
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(maxMs-minMs)))
	time.Sleep(time.Duration(int64(minMs)+n.Int64()) * time.Millisecond)
}
