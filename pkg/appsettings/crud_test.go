package appsettings

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestSettingCRUD(t *testing.T) {
	testutils.WithTestDB(t)

	// Test Set and Get
	err := SetSetting("test_key", "test_value")
	assert.NoError(t, err)

	val, err := GetSetting("test_key")
	assert.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Test Update
	err = SetSetting("test_key", "new_value")
	assert.NoError(t, err)

	val, err = GetSetting("test_key")
	assert.NoError(t, err)
	assert.Equal(t, "new_value", val)

	// Test GetAllSettings
	all, err := GetAllSettings()
	assert.NoError(t, err)
	assert.Contains(t, all, "test_key")
	assert.Equal(t, "new_value", all["test_key"])
}
