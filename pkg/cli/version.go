package cli

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var Version = "dev"

func RunVersion(_ *cli.Context) error {
	fmt.Println(Version)
	return nil
}
