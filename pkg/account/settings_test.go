package account

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestHandleGetSettings(t *testing.T) {
	testutils.WithTestDB(t)
	rr := testutils.MockJSONRequest(t, "", "GET", "/account/settings", HandleGetSettings)
	assert.Contains(t, string(rr), "auth_mode")
}
