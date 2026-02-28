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
				},
				Action: appCli.RunInit,
			},
			{
				Name:   "start",
				Usage:  "Start the HTTP server",
				Action: appCli.RunStart,
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
