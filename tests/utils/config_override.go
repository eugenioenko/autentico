package testutils

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
)

func WithConfigOverride(t *testing.T, override func()) {
	originalValues := config.GetOriginal()
	originalBootstrap := *config.GetBootstrap()

	t.Cleanup(func() {
		config.Values = originalValues
		config.Bootstrap = originalBootstrap
	})

	override()
}
