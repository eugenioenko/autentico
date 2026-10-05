package client

import (
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	testutils "github.com/eugenioenko/autentico/tests/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func strPtr(s string) *string { return &s }
func boolPtr(b bool) *bool    { return &b }

func TestCreateClient_AppMetadata(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:    "Wiki",
		RedirectURIs:  []string{"https://wiki.example.com/callback"},
		Description:   "Team wiki",
		LogoURI:       "https://wiki.example.com/logo.png",
		ClientURI:     "https://wiki.example.com",
		ShowInAccount: true,
	})
	require.NoError(t, err)
	assert.Equal(t, "Team wiki", created.Description)
	assert.True(t, created.ShowInAccount)

	c, err := ClientByClientID(created.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "Team wiki", c.Description)
	assert.Equal(t, "https://wiki.example.com/logo.png", c.LogoURI)
	assert.Equal(t, "https://wiki.example.com", c.ClientURI)
	assert.True(t, c.ShowInAccount)
}

func TestCreateClient_ShowInAccountDefaultsFalse(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:   "Hidden",
		RedirectURIs: []string{"https://hidden.example.com/callback"},
	})
	require.NoError(t, err)

	c, err := ClientByClientID(created.ClientID)
	require.NoError(t, err)
	assert.False(t, c.ShowInAccount)
	assert.Equal(t, "", c.Description)
	assert.Equal(t, "", c.LogoURI)
	assert.Equal(t, "", c.ClientURI)
}

func TestUpdateClient_AppMetadata(t *testing.T) {
	testutils.WithTestDB(t)

	created, err := CreateClient(ClientCreateRequest{
		ClientName:    "Wiki",
		RedirectURIs:  []string{"https://wiki.example.com/callback"},
		Description:   "Team wiki",
		LogoURI:       "https://wiki.example.com/logo.png",
		ClientURI:     "https://wiki.example.com",
		ShowInAccount: true,
	})
	require.NoError(t, err)

	require.NoError(t, UpdateClient(created.ClientID, ClientUpdateRequest{ClientName: "Wiki 2"}))
	c, err := ClientByClientID(created.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "Team wiki", c.Description, "omitted fields are preserved")
	assert.True(t, c.ShowInAccount)

	require.NoError(t, UpdateClient(created.ClientID, ClientUpdateRequest{
		Description:   strPtr(""),
		LogoURI:       strPtr(""),
		ClientURI:     strPtr("https://docs.example.com"),
		ShowInAccount: boolPtr(false),
	}))
	c, err = ClientByClientID(created.ClientID)
	require.NoError(t, err)
	assert.Equal(t, "", c.Description, "empty string clears the field")
	assert.Equal(t, "", c.LogoURI)
	assert.Equal(t, "https://docs.example.com", c.ClientURI)
	assert.False(t, c.ShowInAccount)
}

func TestListAccountApps(t *testing.T) {
	testutils.WithTestDB(t)

	mk := func(id, name string, show bool) {
		_, err := CreateClientWithID(id, ClientCreateRequest{
			ClientName:    name,
			RedirectURIs:  []string{"https://" + id + ".example.com/callback"},
			ShowInAccount: show,
		})
		require.NoError(t, err)
	}
	mk("zeta", "zeta", true)
	mk("alpha", "Alpha", true)
	mk("hidden", "Hidden", false)
	mk("disabled", "Disabled", true)
	mk(config.AdminClientID, "Admin", true)
	mk(config.AccountClientID, "Account", true)
	require.NoError(t, UpdateClient("disabled", ClientUpdateRequest{IsActive: boolPtr(false)}))

	apps, err := ListAccountApps()
	require.NoError(t, err)
	ids := make([]string, len(apps))
	for i, a := range apps {
		ids[i] = a.ClientID
	}
	assert.Equal(t, []string{"alpha", "zeta"}, ids)
}

func TestListAccountApps_Empty(t *testing.T) {
	testutils.WithTestDB(t)

	apps, err := ListAccountApps()
	require.NoError(t, err)
	assert.Empty(t, apps)
	assert.NotNil(t, apps)
}

func TestValidateAppMetadata(t *testing.T) {
	base := ClientCreateRequest{ClientName: "App", RedirectURIs: []string{"https://app.example.com/cb"}}

	valid := []string{
		"",
		"https://app.example.com",
		"https://app.example.com/path?x=1",
		"http://localhost:3000",
		"http://127.0.0.1:8080/",
		"http://[::1]:8080/",
	}
	for _, uri := range valid {
		req := base
		req.ClientURI = uri
		req.LogoURI = uri
		assert.NoError(t, ValidateClientCreateRequest(req), uri)
	}

	invalid := []string{
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"http://app.example.com",
		"ftp://app.example.com",
		"//app.example.com",
		"/relative/path",
		"https://user:pass@app.example.com",
		"https://app.example.com/\"onerror=",
		"https://app.example.com/<script>",
	}
	for _, uri := range invalid {
		req := base
		req.ClientURI = uri
		assert.Error(t, ValidateClientCreateRequest(req), "client_uri "+uri)
		req = base
		req.LogoURI = uri
		assert.Error(t, ValidateClientCreateRequest(req), "logo_uri "+uri)
		assert.Error(t, ValidateClientUpdateRequest(ClientUpdateRequest{ClientURI: strPtr(uri)}), "update client_uri "+uri)
	}

	req := base
	req.Description = "<b>bold</b>"
	assert.Error(t, ValidateClientCreateRequest(req))
	assert.Error(t, ValidateClientUpdateRequest(ClientUpdateRequest{Description: strPtr("<img>")}))
	assert.NoError(t, ValidateClientUpdateRequest(ClientUpdateRequest{Description: strPtr("")}))
	assert.NoError(t, ValidateClientUpdateRequest(ClientUpdateRequest{}))
}
