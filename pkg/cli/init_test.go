package cli

import (
	"flag"
	"os"
	"testing"

	"github.com/urfave/cli/v2"
	"github.com/stretchr/testify/assert"
)

func TestRunInit(t *testing.T) {
	// Create a temporary directory for the test to avoid messing with real .env
	tmpDir, err := os.MkdirTemp("", "autentico-cli-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("url", "http://test.com", "")
	set.Bool("dev", false, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunInit(ctx)
	assert.NoError(t, err)

	// Verify .env was created
	_, err = os.Stat(".env")
	assert.NoError(t, err)

	// Verify .env content roughly
	content, _ := os.ReadFile(".env")
	sContent := string(content)
	assert.Contains(t, sContent, "AUTENTICO_APP_URL=http://test.com")
	assert.Contains(t, sContent, "AUTENTICO_PRIVATE_KEY=")
	// Production mode: secure cookies must be true
	assert.Contains(t, sContent, "AUTENTICO_CSRF_SECURE_COOKIE=true")
	assert.Contains(t, sContent, "AUTENTICO_REFRESH_TOKEN_SECURE=true")
	assert.Contains(t, sContent, "AUTENTICO_IDP_SESSION_SECURE=true")

	// Test re-init error
	err = RunInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ".env already exists")
}

func TestRunInit_DevMode(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "autentico-cli-dev-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("url", "http://localhost:9999", "")
	set.Bool("dev", false, "")
	ctx := cli.NewContext(app, set, nil)
	_ = set.Set("dev", "true")

	err = RunInit(ctx)
	assert.NoError(t, err)

	content, _ := os.ReadFile(".env")
	sContent := string(content)
	// Dev mode: all secure cookie flags must be false
	assert.Contains(t, sContent, "AUTENTICO_CSRF_SECURE_COOKIE=false")
	assert.Contains(t, sContent, "AUTENTICO_REFRESH_TOKEN_SECURE=false")
	assert.Contains(t, sContent, "AUTENTICO_IDP_SESSION_SECURE=false")
	// Secrets must still be generated
	assert.Contains(t, sContent, "AUTENTICO_PRIVATE_KEY=")
	assert.NotContains(t, sContent, "AUTENTICO_CSRF_SECURE_COOKIE=true")
}

func TestRunInit_InvalidURL(t *testing.T) {
	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("url", "invalid-url-no-scheme", "")
	ctx := cli.NewContext(app, set, nil)

	err := RunInit(ctx)
	assert.Error(t, err)
}

func TestRunInit_DefaultURL(t *testing.T) {
	tmpDir, _ := os.MkdirTemp("", "autentico-cli-default-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)

	err := RunInit(ctx)
	assert.NoError(t, err)

	content, _ := os.ReadFile(".env")
	assert.Contains(t, string(content), "AUTENTICO_APP_URL=http://localhost:9999")
}

func TestRandomHex(t *testing.T) {
	h1, err := randomHex(16)
	assert.NoError(t, err)
	assert.Len(t, h1, 32) // 16 bytes = 32 hex chars

	h2, _ := randomHex(16)
	assert.NotEqual(t, h1, h2)
}

func TestRunInit_URLParsingError(t *testing.T) {
	// Use a temporary directory
	tmpDir, _ := os.MkdirTemp("", "autentico-cli-parsing-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()

	// Invalid URL (unparseable)
	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("url", "http://[::1]:80:80", "") // Invalid port
	ctx := cli.NewContext(app, set, nil)
	
	err := RunInit(ctx)
	assert.Error(t, err)

	// Missing scheme/host
	_ = set.Set("url", "just-a-string")
	err = RunInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must include scheme and host")
}

func TestRunInit_EnvDirectoryError(t *testing.T) {
	// Create a temporary directory for the test
	tmpDir, _ := os.MkdirTemp("", "autentico-cli-write-test")
	defer func() { _ = os.RemoveAll(tmpDir) }()
	
	origDir, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origDir) }()
	
	// Create a directory named .env so WriteFile fails
	_ = os.Mkdir(".env", 0755)
	
	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("url", "http://test.com", "")
	ctx := cli.NewContext(app, set, nil)
	
	err := RunInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), ".env already exists")
}
