package cli

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunVersion(t *testing.T) {
	err := RunVersion(nil)
	assert.NoError(t, err)
}

func TestVersionNotEmpty(t *testing.T) {
	assert.NotEmpty(t, Version)
	assert.Contains(t, Version, "v.")
}
