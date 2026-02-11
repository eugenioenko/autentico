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

func main() {
	app := &cli.App{
		Name:  "autentico",
		Usage: "OpenID Connect Identity Provider",
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "Initialize the database with an admin user and admin UI client",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:     "email",
						Usage:    "Admin email address",
						Required: true,
					},
					&cli.StringFlag{
						Name:     "password",
						Usage:    "Admin password",
						Required: true,
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
