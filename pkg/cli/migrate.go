package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/eugenioenko/autentico/pkg/db"
	"github.com/eugenioenko/autentico/pkg/db/migrations"
)

func RunMigrate(_ *cli.Context) error {
	config.InitBootstrap()
	bs := config.GetBootstrap()

	if _, err := db.InitDB(bs.DbFilePath); err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.CloseDB()

	database := db.GetDB()

	if err := migrations.Check(database); err == nil {
		fmt.Println("Already up to date.")
		return nil
	}

	var current int
	if err := database.QueryRow("PRAGMA user_version").Scan(&current); err != nil {
		return fmt.Errorf("failed to read current schema version: %w", err)
	}

	fmt.Printf("Current schema version : %d\n", current)
	fmt.Printf("Target schema version  : %d\n", migrations.SchemaVersion)
	fmt.Println()
	fmt.Println("WARNING: Migrations are irreversible. Back up your database file before proceeding.")
	fmt.Printf("  DB file: %s\n", bs.DbFilePath)
	fmt.Println()
	fmt.Printf("Type '%d' to confirm and apply migrations: ", migrations.SchemaVersion)

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}
	input = strings.TrimSpace(input)

	if input != fmt.Sprintf("%d", migrations.SchemaVersion) {
		fmt.Println("Migration cancelled.")
		return nil
	}

	return migrations.Run(database, true)
}
