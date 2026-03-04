package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashSHA256(t *testing.T) {
	input := "password123"
	// Correct hash for "password123" is ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f
	expected := "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f"
	
	actual := HashSHA256(input)
	assert.Equal(t, expected, actual)
}

func TestPtr(t *testing.T) {
	val := "test"
	ptr := Ptr(val)
	assert.Equal(t, val, *ptr)

	valInt := 123
	ptrInt := Ptr(valInt)
	assert.Equal(t, valInt, *ptrInt)
}
