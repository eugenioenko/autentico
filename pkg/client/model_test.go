package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClient_GetRedirectURIs(t *testing.T) {
	client := &Client{
		RedirectURIs: `["http://localhost:3000/callback", "http://example.com/callback"]`,
	}

	uris := client.GetRedirectURIs()
	assert.Equal(t, []string{"http://localhost:3000/callback", "http://example.com/callback"}, uris)
}

func TestClient_GetRedirectURIs_Empty(t *testing.T) {
	client := &Client{
		RedirectURIs: `[]`,
	}

	uris := client.GetRedirectURIs()
	assert.Empty(t, uris)
}

func TestClient_GetGrantTypes(t *testing.T) {
	client := &Client{
		GrantTypes: `["authorization_code", "refresh_token"]`,
	}

	types := client.GetGrantTypes()
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, types)
}

func TestClient_GetResponseTypes(t *testing.T) {
	client := &Client{
		ResponseTypes: `["code", "token"]`,
	}

	types := client.GetResponseTypes()
	assert.Equal(t, []string{"code", "token"}, types)
}

func TestClient_ToInfoResponse(t *testing.T) {
	client := &Client{
		ClientID:                "test-client-id",
		ClientSecret:            "hashed-secret",
		ClientName:              "Test App",
		ClientType:              "confidential",
		RedirectURIs:            `["http://localhost/callback"]`,
		GrantTypes:              `["authorization_code"]`,
		ResponseTypes:           `["code"]`,
		Scopes:                  "openid profile",
		TokenEndpointAuthMethod: "client_secret_basic",
		IsActive:                true,
	}

	info := client.ToInfoResponse()

	assert.Equal(t, "test-client-id", info.ClientID)
	assert.Equal(t, "Test App", info.ClientName)
	assert.Equal(t, "confidential", info.ClientType)
	assert.Equal(t, []string{"http://localhost/callback"}, info.RedirectURIs)
	assert.Equal(t, []string{"authorization_code"}, info.GrantTypes)
	assert.Equal(t, []string{"code"}, info.ResponseTypes)
	assert.Equal(t, "openid profile", info.Scopes)
	assert.Equal(t, "client_secret_basic", info.TokenEndpointAuthMethod)
	assert.True(t, info.IsActive)
}

func TestValidateClientCreateRequest(t *testing.T) {
	tests := []struct {
		name    string
		request ClientCreateRequest
		wantErr bool
	}{
		{
			name: "valid request",
			request: ClientCreateRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				GrantTypes:   []string{"authorization_code"},
			},
			wantErr: false,
		},
		{
			name: "missing client name",
			request: ClientCreateRequest{
				RedirectURIs: []string{"http://localhost:3000/callback"},
			},
			wantErr: true,
		},
		{
			name: "missing redirect URIs",
			request: ClientCreateRequest{
				ClientName: "Test App",
			},
			wantErr: true,
		},
		{
			name: "invalid grant type",
			request: ClientCreateRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				GrantTypes:   []string{"invalid_grant"},
			},
			wantErr: true,
		},
		{
			name: "invalid response type",
			request: ClientCreateRequest{
				ClientName:    "Test App",
				RedirectURIs:  []string{"http://localhost:3000/callback"},
				ResponseTypes: []string{"invalid_type"},
			},
			wantErr: true,
		},
		{
			name: "invalid client type",
			request: ClientCreateRequest{
				ClientName:   "Test App",
				RedirectURIs: []string{"http://localhost:3000/callback"},
				ClientType:   "invalid",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientCreateRequest(tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateRedirectURIs(t *testing.T) {
	tests := []struct {
		name    string
		uris    []string
		wantErr bool
	}{
		{
			name:    "valid URIs",
			uris:    []string{"http://localhost:3000/callback", "https://example.com/auth"},
			wantErr: false,
		},
		{
			name:    "invalid URI",
			uris:    []string{"not-a-valid-uri"},
			wantErr: true,
		},
		{
			name:    "mixed valid and invalid",
			uris:    []string{"http://localhost/callback", "invalid"},
			wantErr: true,
		},
		{
			name:    "empty URI in list",
			uris:    []string{"http://localhost/callback", ""},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURIs(tt.uris)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateClientUpdateRequest(t *testing.T) {
	tests := []struct {
		name    string
		request ClientUpdateRequest
		wantErr bool
	}{
		{
			name: "valid update",
			request: ClientUpdateRequest{
				ClientName: "Updated Name",
			},
			wantErr: false,
		},
		{
			name:    "empty request (valid)",
			request: ClientUpdateRequest{},
			wantErr: false,
		},
		{
			name: "invalid grant type",
			request: ClientUpdateRequest{
				GrantTypes: []string{"invalid_grant"},
			},
			wantErr: true,
		},
		{
			name: "client name too long",
			request: ClientUpdateRequest{
				ClientName: string(make([]byte, 300)),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateClientUpdateRequest(tt.request)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
