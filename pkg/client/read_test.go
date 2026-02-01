package client

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/stretchr/testify/assert"
)

func TestClientByClientID(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create a client first
	request := ClientCreateRequest{
		ClientName:   "Test App",
		RedirectURIs: []string{"http://localhost:3000/callback"},
	}

	created, err := CreateClient(request)
	assert.NoError(t, err)

	// Retrieve the client
	client, err := ClientByClientID(created.ClientID)
	assert.NoError(t, err)
	assert.Equal(t, created.ClientID, client.ClientID)
	assert.Equal(t, "Test App", client.ClientName)
	assert.True(t, client.IsActive)
}

func TestClientByClientIDNotFound(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	_, err = ClientByClientID("nonexistent-client")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestListClients(t *testing.T) {
	_, err := db.InitTestDB("../../db/test.db")
	if err != nil {
		t.Fatalf("Failed to initialize test database: %v", err)
	}
	defer db.CloseDB()

	// Create some clients
	_, err = CreateClient(ClientCreateRequest{
		ClientName:   "App 1",
		RedirectURIs: []string{"http://localhost:3001/callback"},
	})
	assert.NoError(t, err)

	_, err = CreateClient(ClientCreateRequest{
		ClientName:   "App 2",
		RedirectURIs: []string{"http://localhost:3002/callback"},
	})
	assert.NoError(t, err)

	// List clients
	clients, err := ListClients()
	assert.NoError(t, err)
	assert.Len(t, clients, 2)
}
