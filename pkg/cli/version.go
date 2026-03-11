package cli

import (
	"fmt"

	"github.com/urfave/cli/v2"
)

var Version = "v.1.4.2"

func RunVersion(_ *cli.Context) error {
	fmt.Println(Version)
	return nil
}
