package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
	"github.com/eugenioenko/autentico/pkg/totpsecret"
)

func RunMigrate(c *cli.Context) error {
	if err := config.InitBootstrap(); err != nil {
		return err
	}
	bs := config.GetBootstrap()
	// RFC 6238 §5.1: never start an irreversible upgrade without its persistent key.
	if err := totpsecret.ValidateKey(bs.TotpEncryptionKey); err != nil {
		return err
	}

	approved := c.IntSlice("approve-major")
	if err := migrations.ValidateApprovals(approved); err != nil {
		return err
	}
	if err := migrations.RecoverFile(bs.DbFilePath); err != nil {
		return err
	}
	current, majorVersions, err := migrations.InspectFile(bs.DbFilePath)
	if err != nil {
		return err
	}
	if current == migrations.SchemaVersion {
		if err := migrations.ValidateCurrentFile(bs.DbFilePath); err != nil {
			return err
		}
		fmt.Println("Already up to date.")
		return nil
	}
	if current > migrations.SchemaVersion {
		return fmt.Errorf("database schema v%d is newer than this binary (v%d)", current, migrations.SchemaVersion)
	}

	fmt.Printf("Current schema version : %d\n", current)
	fmt.Printf("Target schema version  : %d\n", migrations.SchemaVersion)
	fmt.Println()
	fmt.Println("Major migrations create a protected backup automatically and restore it on failure.")
	fmt.Println("Stop all Autentico instances and other database users before proceeding.")
	fmt.Printf("  DB file: %s\n", bs.DbFilePath)
	fmt.Println()
	confirmation := fmt.Sprintf("%d", migrations.SchemaVersion)
	allApproved := len(approved) > 0 && len(migrations.MissingMajorApprovals(majorVersions, approved)) == 0
	if len(majorVersions) > 0 {
		fmt.Printf("Major schema migrations: %v\n", majorVersions)
		for _, version := range majorVersions {
			switch version {
			case 15:
				fmt.Println("WARNING: All access/refresh tokens, OAuth/SSO sessions, and pending login grants will be invalidated. Everyone must sign in again.")
			case 17:
				fmt.Println("TOTP enrollments will be encrypted in place and preserved. Keep AUTENTICO_TOTP_ENCRYPTION_KEY for future restarts and database restores.")
			}
		}
	}
	// Explicit approvals also keep deployment jobs noninteractive for new
	// volumes and later routine upgrades. A new major still needs approval.
	if allApproved {
		return migrations.RunFile(bs.DbFilePath, true, approved...)
	}
	fmt.Printf("Type '%s' to confirm and apply migrations: ", confirmation)

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(input)

	if input != confirmation {
		fmt.Println("Migration cancelled.")
		return nil
	}

	return migrations.RunFile(bs.DbFilePath, true, majorVersions...)
}
