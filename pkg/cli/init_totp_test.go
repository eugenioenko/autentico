package cli

import (
	"flag"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/eugenioenko/autentico/pkg/totpsecret"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestInitAddsOnlyMissingTotpKey(t *testing.T) {
	for _, ending := range []string{"", "\n", "\r\n"} {
		t.Run(ending, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, ".env")
			original := "# keep comments\nAUTENTICO_PRIVATE_KEY=keep-rsa\nAUTENTICO_REFRESH_TOKEN_SECRET=keep-refresh\nCUSTOM=keep-value" + ending
			require.NoError(t, os.WriteFile(path, []byte(original), 0600))
			set := flag.NewFlagSet("init", flag.ContinueOnError)
			set.String("output", dir, "")
			ctx := cli.NewContext(&cli.App{}, set, nil)
			require.NoError(t, RunInit(ctx))
			first, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, original, string(first[:len(original)]))
			values, err := godotenv.Read(path)
			require.NoError(t, err)
			require.NoError(t, totpsecret.ValidateKey(values[totpsecret.EnvName]))
			require.Equal(t, "keep-rsa", values["AUTENTICO_PRIVATE_KEY"])
			require.NoError(t, RunInit(ctx))
			again, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, first, again)
		})
	}
}

func TestInitPreservesInvalidExistingKeyForOperatorCorrection(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	original := totpsecret.EnvName + "=broken-key\nAUTENTICO_PRIVATE_KEY=keep\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0600))
	set := flag.NewFlagSet("init", flag.ContinueOnError)
	set.String("output", dir, "")
	err := RunInit(cli.NewContext(&cli.App{}, set, nil))
	require.ErrorContains(t, err, totpsecret.EnvName)
	require.NotContains(t, err.Error(), "broken-key")
	again, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, original, string(again))
}

func TestConcurrentInitDoesNotReplaceKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	const original = "AUTENTICO_PRIVATE_KEY=existing-key\n"
	require.NoError(t, os.WriteFile(path, []byte(original), 0600))
	start, results := make(chan struct{}), make(chan error, 20)
	for range 20 {
		go func() {
			set := flag.NewFlagSet("init", flag.ContinueOnError)
			set.String("output", dir, "")
			<-start
			results <- RunInit(cli.NewContext(&cli.App{}, set, nil))
		}()
	}
	close(start)
	winners := 0
	for range 20 {
		if err := <-results; err == nil {
			winners++
		} else {
			require.Contains(t, err.Error(), "in use")
		}
	}
	require.Positive(t, winners)
	content, err := os.ReadFile(path)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(string(content), original))
	require.Equal(t, 1, strings.Count(string(content), totpsecret.EnvName+"="))
	values, err := godotenv.Unmarshal(string(content))
	require.NoError(t, err)
	require.NoError(t, totpsecret.ValidateKey(values[totpsecret.EnvName]))
}

func TestInitPreservesGroupReadAccess(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX group permissions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, ".env")
	require.NoError(t, os.WriteFile(path, []byte("# service group reads this config\n"), 0640))
	set := flag.NewFlagSet("init", flag.ContinueOnError)
	set.String("output", dir, "")
	require.NoError(t, RunInit(cli.NewContext(&cli.App{}, set, nil)))
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0640), info.Mode().Perm())
}
