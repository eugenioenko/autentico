package client

import (
	"testing"

	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
)

func TestDeleteClient(t *testing.T) {
	testutils.WithTestDB(t)

	// Create a client
	request := ClientCreateRequest{
		ClientName:   "Delete Me",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		ClientType:   "public",
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Verify client exists and is active
	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.True(t, client.IsActive)

	// Delete the client
	err = DeleteClient(created.ClientID)
	assert.NoError(t, err)

	// Verify client is now inactive
	client, err = ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.False(t, client.IsActive)
}

func TestDeleteClient_NotFound(t *testing.T) {
	testutils.WithTestDB(t)

	err := DeleteClient("nonexistent-client-id")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}
