package testutils

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
)

func WithConfigOverride(t *testing.T, override func()) {
	original := config.GetOriginal()

	t.Cleanup(func() {
		config.Values = original
	})

	override()
}
