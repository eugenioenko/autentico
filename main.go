package main

import (
	"log"
	"os"

	"github.com/urfave/cli/v2"

	appCli "github.com/eugenioenko/autentico/pkg/cli"
)

// @title Autentico OIDC
// @version 1.0
// @description Self-contained OAuth 2.0 / OpenID Connect (OIDC) Identity Provider built with Go and SQLite.
// @host localhost:9999
// @BasePath /

// @tag.name oauth2
// @tag.description OAuth2 and OpenID Connect endpoints (authorize, token, introspect, revoke, userinfo, logout, discovery)
// @tag.name admin-client
// @tag.description Client registration and management (also available via /oauth2/register per RFC 7591)
// @tag.name admin-settings
// @tag.description System settings, statistics, audit logs, and SMTP configuration
// @tag.name admin-users
// @tag.description User account management (CRUD, deactivate, reactivate, unlock)
// @tag.name admin-sessions
// @tag.description OAuth session management
// @tag.name admin-groups
// @tag.description Group and membership management
// @tag.name admin-federation
// @tag.description Federation / external identity provider configuration
// @tag.name admin-deletion
// @tag.description Account deletion request review and approval
// @tag.name account
// @tag.description User profile and account settings
// @tag.name account-security
// @tag.description Password, sessions, passkeys, MFA, and trusted devices
// @tag.name account-federation
// @tag.description Connected external identity providers
// @tag.name account-deletion
// @tag.description Account deletion requests
// @tag.name health
// @tag.description Server health check

// @securityDefinitions.apikey AdminAuth
// @in header
// @name Authorization
// @description Admin access token — requires admin role and autentico-admin audience. Type "Bearer" followed by your token.

// @securityDefinitions.apikey UserAuth
// @in header
// @name Authorization
// @description User access token — any valid bearer token. Type "Bearer" followed by your token.

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
						Name:  "no-auto-migrate",
						Usage: "Do not automatically apply pending database migrations on startup",
					},
					&cli.BoolFlag{
						Name:  "auto-setup",
						Usage: "Generate a .env file with secure defaults if one does not exist",
					},
					&cli.StringFlag{
						Name:  "url",
						Usage: "Application URL for --auto-setup (e.g. https://auth.example.com)",
					},
					&cli.BoolFlag{
						Name:  "dev",
						Usage: "With --auto-setup, disable secure cookie flags for local HTTP development",
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
						EnvVars:  []string{"AUTENTICO_ADMIN_USERNAME"},
						Required: true,
					},
					&cli.StringFlag{
						Name:     "password",
						Usage:    "Admin password",
						EnvVars:  []string{"AUTENTICO_ADMIN_PASSWORD"},
						Required: true,
					},
					&cli.StringFlag{
						Name:    "email",
						Usage:   "Admin email address",
						EnvVars: []string{"AUTENTICO_ADMIN_EMAIL"},
					},
					&cli.BoolFlag{
						Name:  "auto-migrate",
						Usage: "Automatically apply pending database migrations",
					},
					&cli.BoolFlag{
						Name:    "enable-admin-password-grant",
						Usage:   "Seed the autentico-admin client with the password (ROPC) grant so admin-API tokens can be obtained headlessly (for CI/CD). MFA and account lockout still apply.",
						EnvVars: []string{"AUTENTICO_ENABLE_ADMIN_PASSWORD_GRANT"},
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
