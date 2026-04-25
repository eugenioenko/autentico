package cli

import (
	"fmt"
	"log"
	"path/filepath"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/appsettings"
	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	"github.com/eugenioenko/autentico/pkg/user"
)

// RunOnboard creates the first admin account via CLI, mirroring the /onboard
// browser flow. It only works once — same guards as the HTTP handler.
func RunOnboard(c *cli.Context) error {
	config.InitBootstrap()
	bs := config.GetBootstrap()

	if _, err := db.InitDB(bs.DbFilePath); err != nil {
		absPath, _ := filepath.Abs(bs.DbFilePath)
		return fmt.Errorf("failed to initialize database at %s: %w", absPath, err)
	}
	defer db.CloseDB()

	if err := migrations.Run(db.GetDB(), true); err != nil {
		return err
	}

	if err := appsettings.EnsureDefaults(); err != nil {
		log.Printf("warning: could not ensure settings defaults: %v", err)
	}
	if err := appsettings.LoadIntoConfig(); err != nil {
		log.Printf("warning: could not load settings from DB: %v", err)
	}

	if err := executeOnboard(c.String("username"), c.String("password"), c.String("email")); err != nil {
		return err
	}

	// Seed the admin client here (rather than waiting for `autentico start`) so the
	// --enable-admin-password-grant flag takes effect. Idempotent: seedAdminClient
	// skips if the client already exists.
	seedAdminClient(c.Bool("enable-admin-password-grant"))
	return nil
}

// executeOnboard contains the core onboarding logic, separated from bootstrap
// so it can be tested with a pre-initialized database.
func executeOnboard(username, password, email string) error {
	// Same guards as the /onboard HTTP handler.
	if appsettings.IsOnboarded() {
		return fmt.Errorf("onboarding already completed")
	}
	count, err := user.CountUsers()
	if err != nil {
		return fmt.Errorf("failed to check existing users: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("users already exist; onboarding is only available on a fresh database")
	}

	req := user.UserCreateRequest{Username: username, Password: password, Email: email}
	if err := user.ValidateUserCreateRequest(req); err != nil {
		return fmt.Errorf("validation error: %w", err)
	}

	usr, err := user.CreateUser(username, password, email)
	if err != nil {
		return fmt.Errorf("failed to create admin account: %w", err)
	}

	if err := user.UpdateUser(usr.ID, user.UserUpdateRequest{Email: usr.Email, Role: "admin"}); err != nil {
		return fmt.Errorf("failed to set admin role: %w", err)
	}

	if err := appsettings.SetSetting("onboarded", "true"); err != nil {
		return fmt.Errorf("failed to mark onboarding complete: %w", err)
	}
	_ = appsettings.LoadIntoConfig()

	fmt.Println("Onboarding complete.")
	fmt.Printf("  Username: %s\n", usr.Username)
	fmt.Printf("  Email:    %s\n", usr.Email)
	fmt.Printf("  Role:     admin\n")

	return nil
}
