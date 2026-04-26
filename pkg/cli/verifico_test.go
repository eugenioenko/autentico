package cli

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"

	"github.com/eugenioenko/autentico/pkg/verifico"
)

func verificoWorkerServer(secret string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", verifico.HandleVerify(secret))
	mux.HandleFunc("POST /ping", verifico.HandlePing(secret))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})
	return httptest.NewServer(mux)
}

func TestRunVerificoInit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "my-shared-secret", "")
	set.String("url", "http://0.0.0.0:5050", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.NoError(t, err)

	content, _ := os.ReadFile(tmpDir + "/.env")
	sContent := string(content)
	assert.Contains(t, sContent, "AUTENTICO_VERIFICO_SECRET=my-shared-secret")
	assert.Contains(t, sContent, "AUTENTICO_VERIFICO_URL=http://0.0.0.0:5050")
}

func TestRunVerificoInit_CustomURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-url-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "s", "")
	set.String("url", "http://192.168.1.10:6060", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.NoError(t, err)

	content, _ := os.ReadFile(tmpDir + "/.env")
	assert.Contains(t, string(content), "AUTENTICO_VERIFICO_URL=http://192.168.1.10:6060")
}

func TestRunVerificoInit_MissingSecret(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-nosecret-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "", "")
	set.String("url", "http://0.0.0.0:5050", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "--secret is required")
}

func TestRunVerificoInit_AlreadyExists(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-exists-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	_ = os.WriteFile(tmpDir+"/.env", []byte("existing"), 0600)

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "s", "")
	set.String("url", "http://0.0.0.0:5050", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestRunVerificoInit_InvalidURL(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-badurl-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "s", "")
	set.String("url", "no-scheme", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must include scheme and host")
}

func TestRunVerificoInit_TrailingSlash(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "verifico-init-slash-test")
	assert.NoError(t, err)
	defer func() { _ = os.RemoveAll(tmpDir) }()

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	set.String("secret", "s", "")
	set.String("url", "http://0.0.0.0:5050/", "")
	set.String("output", tmpDir, "")
	ctx := cli.NewContext(app, set, nil)

	err = RunVerificoInit(ctx)
	assert.NoError(t, err)

	content, _ := os.ReadFile(tmpDir + "/.env")
	assert.Contains(t, string(content), "AUTENTICO_VERIFICO_URL=http://0.0.0.0:5050")
	assert.NotContains(t, string(content), "AUTENTICO_VERIFICO_URL=http://0.0.0.0:5050/")
}

func TestRunVerificoTest_Disabled(t *testing.T) {
	t.Setenv("AUTENTICO_VERIFICO_ENABLED", "false")

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)

	err := RunVerificoTest(ctx)
	assert.NoError(t, err)
}

func TestRunVerificoTest_NoWorkers(t *testing.T) {
	t.Setenv("AUTENTICO_VERIFICO_ENABLED", "true")
	t.Setenv("AUTENTICO_VERIFICO_WORKERS", "")

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)

	err := RunVerificoTest(ctx)
	assert.NoError(t, err)
}

func TestRunVerificoTest_WithWorker(t *testing.T) {
	ts := verificoWorkerServer("test-secret")
	defer ts.Close()

	addr := strings.TrimPrefix(ts.URL, "http://")
	t.Setenv("AUTENTICO_VERIFICO_ENABLED", "true")
	t.Setenv("AUTENTICO_VERIFICO_WORKERS", addr)
	t.Setenv("AUTENTICO_VERIFICO_SECRET", "test-secret")

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)

	err := RunVerificoTest(ctx)
	assert.NoError(t, err)
}

func TestRunVerificoTest_WorkerDown(t *testing.T) {
	t.Setenv("AUTENTICO_VERIFICO_ENABLED", "true")
	t.Setenv("AUTENTICO_VERIFICO_WORKERS", "127.0.0.1:1")
	t.Setenv("AUTENTICO_VERIFICO_SECRET", "test-secret")

	app := &cli.App{Name: "test"}
	set := flag.NewFlagSet("test", flag.ContinueOnError)
	ctx := cli.NewContext(app, set, nil)

	err := RunVerificoTest(ctx)
	assert.NoError(t, err)
}

func TestBuildVerificoEnvContent(t *testing.T) {
	content := buildVerificoEnvContent("http://0.0.0.0:5050", "abc123")
	assert.Contains(t, content, "AUTENTICO_VERIFICO_SECRET=abc123")
	assert.Contains(t, content, "AUTENTICO_VERIFICO_URL=http://0.0.0.0:5050")
	assert.Contains(t, content, "AUTENTICO_MAX_PROCS=0")
}
