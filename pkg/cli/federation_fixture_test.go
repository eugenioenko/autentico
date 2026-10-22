package cli

import (
	"flag"
	"net/http"
	"os"
	"testing"

	"github.com/eugenioenko/autentico/pkg/federation"
	urfave "github.com/urfave/cli/v2"
)

// TestFederationFixtureServer runs the real CLI routes with a local-provider test transport.
// This entry point exists only in a compiled Go test binary, never in the service executable.
func TestFederationFixtureServer(t *testing.T) {
	if os.Getenv("AUTENTICO_TEST_FEDERATION_FIXTURE") != "1" {
		t.Skip("subprocess fixture for the two-instance federation HTTP tests")
	}
	flags := flag.NewFlagSet("federation-fixture", flag.ContinueOnError)
	flags.Bool("auto-setup", false, "")
	flags.Bool("no-auto-migrate", false, "")
	context := urfave.NewContext(nil, flags, nil)
	if err := runStart(context, federation.NewLoginHandler(http.DefaultClient)); err != nil {
		t.Fatal(err)
	}
}
