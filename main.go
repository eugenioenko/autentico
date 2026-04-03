package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"

	appCli "github.com/eugenioenko/autentico/pkg/cli"
)

// @title Autentico OIDC
// @version 1.0
// @description Authentication Service
// @host localhost:9999
// @BasePath /

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and then your access token.

func main() {
	app := &cli.App{
		Name:  "autentico",
		Usage: "OpenID Connect Identity Provider",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Generate a .env configuration file with secure defaults",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "url",
						Usage: "Application URL (e.g. https://auth.example.com)",
						Value: "http://localhost:9999",
					},
					&cli.BoolFlag{
						Name:  "dev",
						Usage: "Disable secure cookie flags for local HTTP development (do not use in production)",
					},
					&cli.StringFlag{
						Name:  "output",
						Usage: "Directory to write the .env file into (default: current directory)",
						Value: ".",
					},
				},
				Action: appCli.RunInit,
			},
			{
				Name:  "start",
				Usage: "Start the HTTP server",
				Flags: []cli.Flag{
					&cli.BoolFlag{
						Name:  "auto-migrate",
						Usage: "Automatically apply pending database migrations on startup",
					},
				},
				Action: appCli.RunStart,
			},
			{
				Name:   "migrate",
				Usage:  "Apply pending database schema migrations",
				Action: appCli.RunMigrate,
			},
			{
				Name:  "onboard",
				Usage: "Create the first admin account (headless alternative to /onboard)",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "username",
						Usage:    "Admin username",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "password",
						Usage:    "Admin password",
						Required: true,
					},
					&cli.StringFlag{
						Name:  "email",
						Usage: "Admin email address",
					},
					&cli.BoolFlag{
						Name:  "auto-migrate",
						Usage: "Automatically apply pending database migrations",
					},
				},
				Action: appCli.RunOnboard,
			},
			{
				Name:   "version",
				Usage:  "Print the version and exit",
				Action: appCli.RunVersion,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
