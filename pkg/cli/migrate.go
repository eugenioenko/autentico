package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

func RunMigrate(c *cli.Context) error {
	config.InitBootstrap()
	bs := config.GetBootstrap()

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
	if current == 0 && len(majorVersions) == 0 && len(approved) > 0 {
		// The same deployment job must work on a new, empty volume too.
		return migrations.RunFile(bs.DbFilePath, true, approved...)
	}
	confirmation := fmt.Sprintf("%d", migrations.SchemaVersion)
	if len(majorVersions) > 0 {
		fmt.Printf("Major schema migrations: %v\n", majorVersions)
		fmt.Println("WARNING: All access/refresh tokens, OAuth/SSO sessions, and pending login grants will be invalidated. Everyone must sign in again.")
		allApproved := true
		for _, version := range majorVersions {
			found := false
			for _, value := range approved {
				found = found || value == version
			}
			allApproved = allApproved && found
		}
		if allApproved {
			return migrations.RunFile(bs.DbFilePath, true, approved...)
		}
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
