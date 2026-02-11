package cli

import (
	"fmt"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/client"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/user"
)

func RunInit(c *cli.Context) error {
	email := c.String("email")
	password := c.String("password")

	if err := config.InitConfig("autentico.json"); err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg := config.Get()
	if len(password) < cfg.ValidationMinPasswordLength {
		return fmt.Errorf("password must be at least %d characters", cfg.ValidationMinPasswordLength)
	}

	if _, err := db.InitDB(cfg.DbFilePath); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	// Create admin user
	resp, err := user.CreateUser(email, password, email)
	if err != nil {
		return fmt.Errorf("failed to create admin user: %w", err)
	}

	if err := user.UpdateUser(resp.ID, email, "admin"); err != nil {
		return fmt.Errorf("failed to set admin role: %w", err)
	}
	fmt.Printf("Admin user created successfully (ID: %s)\n", resp.ID)

	// Create admin UI client
	const adminClientName = "Autentico Admin UI"
	const adminClientID = "autentico-admin"

	existing, err := client.ClientByName(adminClientName)
	if err == nil && existing != nil {
		fmt.Printf("Admin UI client already exists (client_id: %s)\n", existing.ClientID)
		return nil
	}

	redirectURI := cfg.AppURL + "/admin/callback"
	err = client.CreateClientWithID(adminClientID, client.ClientCreateRequest{
		ClientName:              adminClientName,
		RedirectURIs:            []string{redirectURI},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientType:              "public",
		TokenEndpointAuthMethod: "none",
	})
	if err != nil {
		return fmt.Errorf("failed to create admin client: %w", err)
	}

	fmt.Printf("Admin UI client created successfully\n")
	fmt.Printf("  client_id:    %s\n", adminClientID)
	fmt.Printf("  redirect_uri: %s\n", redirectURI)

	return nil
}
