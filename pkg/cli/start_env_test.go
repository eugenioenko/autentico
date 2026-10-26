package cli

import (
	"flag"
	"os"
	"path/filepath"
	"testing"

	"github.com/eugenioenko/autentico/pkg/config"
	"github.com/joho/godotenv"
	"github.com/stretchr/testify/require"
	"github.com/urfave/cli/v2"
)

func TestRunStartEnvFile(t *testing.T) {
	for _, tt := range []struct {
		name       string
		path       string
		absolute   bool
		contents   string
		processURL string
		wantURL    string
		wantError  string
	}{
		{name: "optional default", wantURL: "http://localhost:9999"},
		{name: "default file", contents: "AUTENTICO_APP_URL=https://default.example", wantURL: "https://default.example"},
		{name: "relative path", path: "custom.env", contents: "AUTENTICO_APP_URL=https://custom.example", wantURL: "https://custom.example"},
		{name: "absolute path", path: "custom.env", absolute: true, contents: "AUTENTICO_APP_URL=https://custom.example", wantURL: "https://custom.example"},
		{name: "environment wins", path: "custom.env", contents: "AUTENTICO_APP_URL=https://custom.example", processURL: "https://process.example", wantURL: "https://process.example"},
		{name: "missing file", path: "missing.env", wantError: "failed to load env file"},
		{name: "malformed file", path: "invalid.env", contents: "AUTENTICO_APP_URL=\"unterminated", wantError: "failed to load env file"},
		{name: "directory", path: "directory", wantError: "failed to load env file"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			saved := config.Bootstrap
			t.Cleanup(func() { config.Bootstrap = saved })
			for _, key := range []string{"AUTENTICO_APP_URL", "AUTENTICO_APP_OAUTH_PATH"} {
				t.Setenv(key, "")
				require.NoError(t, os.Unsetenv(key))
			}
			// Stop before opening a DB or listening, after bootstrap has loaded.
			t.Setenv("AUTENTICO_ACCESS_TOKEN_SECRET", "")
			t.Setenv("AUTENTICO_TRUSTED_PROXIES", "")
			if tt.processURL != "" {
				t.Setenv("AUTENTICO_APP_URL", tt.processURL)
			}

			set := flag.NewFlagSet("start", flag.ContinueOnError)
			set.String("env-file", "", "")
			path := ".env"
			if tt.path != "" {
				// A selected file must not fall back to unrelated CWD settings.
				require.NoError(t, os.WriteFile(".env", []byte("AUTENTICO_APP_OAUTH_PATH=/unrelated"), 0600))
				path = tt.path
				if tt.absolute {
					path = filepath.Join(dir, path)
				}
				require.NoError(t, set.Set("env-file", path))
			}
			if tt.contents != "" {
				require.NoError(t, os.WriteFile(path, []byte(tt.contents), 0600))
			}
			if tt.name == "directory" {
				require.NoError(t, os.Mkdir(path, 0700))
			}
			err := RunStart(cli.NewContext(&cli.App{}, set, nil))
			if tt.wantError != "" {
				require.ErrorContains(t, err, tt.wantError)
				return
			}
			require.ErrorContains(t, err, "missing required secrets")
			require.Equal(t, tt.wantURL, config.GetBootstrap().AppURL)
			require.Equal(t, "/oauth2", config.GetBootstrap().AppOAuthPath)
		})
	}
}

func TestAutoGenerateConfigEnvFile(t *testing.T) {
	for _, path := range []string{".env", "custom.env"} {
		t.Run(path, func(t *testing.T) {
			t.Chdir(t.TempDir())
			require.NoError(t, autoGenerateConfig(path, "https://custom.example", false))
			content, err := os.ReadFile(path)
			require.NoError(t, err)
			values, err := godotenv.Unmarshal(string(content))
			require.NoError(t, err)
			require.Equal(t, "https://custom.example", values["AUTENTICO_APP_URL"])
			require.NotEmpty(t, values["AUTENTICO_PRIVATE_KEY"])
			if path != ".env" {
				_, err := os.Stat(".env")
				require.True(t, os.IsNotExist(err))
			}
			require.NoError(t, autoGenerateConfig(path, "https://other.example", false))
			again, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, content, again)
		})
	}
}
