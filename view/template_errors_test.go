package view

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTemplate_NotFound(t *testing.T) {
	_, err := ParseTemplate("nonexistent")
	assert.Error(t, err)
}

func TestParseTemplate_Success(t *testing.T) {
	// Assuming layout.html and login.html exist in the embed FS
	tmpl, err := ParseTemplate("login")
	assert.NoError(t, err)
	assert.NotNil(t, tmpl)
}
