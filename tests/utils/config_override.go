package testutils

import (
	"autentico/pkg/config"
	"testing"
)

func WithConfigOverride(t *testing.T, override func()) {
	original := config.GetOriginal()

	t.Cleanup(func() {
		config.Values = original
	})

	override()
}
