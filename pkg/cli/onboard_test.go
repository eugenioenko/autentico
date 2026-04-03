package cli

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/user"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteOnboard_Success(t *testing.T) {
	testutils.WithTestDB(t)

	err := executeOnboard("admin", "password123", "admin@example.com")
	require.NoError(t, err)

	usr, err := user.UserByUsername("admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", usr.Username)
	assert.Equal(t, "admin@example.com", usr.Email)
	assert.Equal(t, "admin", usr.Role)
	assert.True(t, appsettings.IsOnboarded())
}

func TestExecuteOnboard_AdminRole(t *testing.T) {
	testutils.WithTestDB(t)

	err := executeOnboard("myadmin", "password123", "")
	require.NoError(t, err)

	usr, err := user.UserByUsername("myadmin")
	require.NoError(t, err)
	assert.Equal(t, "admin", usr.Role, "onboard must always create an admin")
}

func TestExecuteOnboard_AlreadyOnboarded(t *testing.T) {
	testutils.WithTestDB(t)

	_ = appsettings.SetSetting("onboarded", "true")

	err := executeOnboard("admin", "password123", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already completed")
}

func TestExecuteOnboard_UsersExist(t *testing.T) {
	testutils.WithTestDB(t)

	_, err := user.CreateUser("existing", "password123", "existing@example.com")
	require.NoError(t, err)

	err = executeOnboard("admin", "password123", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "users already exist")
}

func TestExecuteOnboard_ValidationError_ShortPassword(t *testing.T) {
	testutils.WithTestDB(t)

	err := executeOnboard("admin", "ab", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "validation error")
}

func TestExecuteOnboard_CannotRunTwice(t *testing.T) {
	testutils.WithTestDB(t)

	err := executeOnboard("admin", "password123", "admin@example.com")
	require.NoError(t, err)

	err = executeOnboard("admin2", "password123", "admin2@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already completed")
}
