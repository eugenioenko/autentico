package db

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInitDB(t *testing.T) {
	result, err := InitDB(":memory:")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	t.Cleanup(func() {
		CloseDB()
	})
}

func TestInitTestDB(t *testing.T) {
	result, err := InitTestDB()
	assert.NoError(t, err)
	assert.NotNil(t, result)
	t.Cleanup(func() {
		CloseDB()
	})
}

func TestGetDB(t *testing.T) {
	_, err := InitTestDB()
	assert.NoError(t, err)
	t.Cleanup(func() {
		CloseDB()
	})

	database := GetDB()
	assert.NotNil(t, database)
	assert.NoError(t, database.Ping())
}

func TestCloseDB(t *testing.T) {
	_, err := InitTestDB()
	assert.NoError(t, err)

	CloseDB()
	// After closing, ping should fail
	err = db.Ping()
	assert.Error(t, err)
}
