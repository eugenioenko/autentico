package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	baseDomain = getEnv("BASE_DOMAIN", "demo.autentico.top")
	binary     = getEnv("AUTENTICO_BINARY", "./autentico")
	dataDir    = getEnv("DATA_DIR", "./demos")
	listenAddr = getEnv("LISTEN_ADDR", ":8080")
	demoTTL    = parseDuration(getEnv("DEMO_TTL", "24h"), 24*time.Hour)
)

type instance struct {
	slug      string
	port      int
	cmd       *exec.Cmd
	dir       string
	proxy     *httputil.ReverseProxy
	expiresAt time.Time
}

type registry struct {
	mu        sync.RWMutex
	instances map[string]*instance
}

func main() {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		slog.Error("failed to create data dir", "err", err)
		os.Exit(1)
	}

	reg := &registry{instances: make(map[string]*instance)}
	go reg.runCleanup()

	http.HandleFunc("/launch", reg.handleLaunch)
	http.HandleFunc("/", reg.handleProxy)

	slog.Info("provisioner listening", "addr", listenAddr, "domain", baseDomain)
	if err := http.ListenAndServe(listenAddr, nil); err != nil {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func (r *registry) handleLaunch(w http.ResponseWriter, req *http.Request) {
	inst, err := r.launch()
	if err != nil {
		slog.Error("failed to launch demo", "err", err)
		http.Error(w, "failed to launch demo — please try again", http.StatusInternalServerError)
		return
	}
	target := fmt.Sprintf("https://%s.%s", inst.slug, baseDomain)
	slog.Info("launched demo", "slug", inst.slug, "port", inst.port, "expires", inst.expiresAt.Format(time.RFC3339))
	http.Redirect(w, req, target, http.StatusFound)
}

func (r *registry) handleProxy(w http.ResponseWriter, req *http.Request) {
	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	suffix := "." + baseDomain
	if !strings.HasSuffix(strings.ToLower(host), suffix) {
		http.NotFound(w, req)
		return
	}

	slug := strings.ToUpper(strings.TrimSuffix(strings.ToLower(host), suffix))

	r.mu.RLock()
	inst, ok := r.instances[slug]
	r.mu.RUnlock()

	if !ok {
		expiredPage(w, baseDomain)
		return
	}

	inst.proxy.ServeHTTP(w, req)
}

func (r *registry) launch() (*instance, error) {
	slug, err := generateSlug()
	if err != nil {
		return nil, fmt.Errorf("generate slug: %w", err)
	}

	port, err := freePort()
	if err != nil {
		return nil, fmt.Errorf("find port: %w", err)
	}

	dir := filepath.Join(dataDir, slug)
	if err := os.MkdirAll(filepath.Join(dir, "db"), 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	logFile, err := os.Create(filepath.Join(dir, "autentico.log"))
	if err != nil {
		return nil, fmt.Errorf("create log file: %w", err)
	}

	instanceURL := fmt.Sprintf("https://%s.%s", slug, baseDomain)
	cmd := exec.Command(binary, "start")
	cmd.Env = append(os.Environ(),
		"AUTENTICO_APP_URL="+instanceURL,
		fmt.Sprintf("AUTENTICO_LISTEN_PORT=%d", port),
		"AUTENTICO_DB_FILE_PATH="+filepath.Join(dir, "db", "autentico.db"),
		"AUTENTICO_ACCESS_TOKEN_SECRET="+randomHex(32),
		"AUTENTICO_REFRESH_TOKEN_SECRET="+randomHex(32),
		"AUTENTICO_CSRF_SECRET_KEY="+randomHex(32),
		"AUTENTICO_APP_ENABLE_CORS=true",
		"AUTENTICO_CSRF_SECURE_COOKIE=true",
		"AUTENTICO_REFRESH_TOKEN_SECURE=true",
		"AUTENTICO_IDP_SESSION_SECURE=true",
	)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		logFile.Close()
		return nil, fmt.Errorf("start autentico: %w", err)
	}

	if err := waitForPort(port, 10*time.Second); err != nil {
		cmd.Process.Kill()
		logFile.Close()
		return nil, fmt.Errorf("autentico did not start: %w", err)
	}

	target, _ := url.Parse(fmt.Sprintf("http://localhost:%d", port))
	proxy := httputil.NewSingleHostReverseProxy(target)

	inst := &instance{
		slug:      slug,
		port:      port,
		cmd:       cmd,
		dir:       dir,
		proxy:     proxy,
		expiresAt: time.Now().Add(demoTTL),
	}

	r.mu.Lock()
	r.instances[slug] = inst
	r.mu.Unlock()

	return inst, nil
}

func (r *registry) runCleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		r.mu.Lock()
		for slug, inst := range r.instances {
			if time.Now().After(inst.expiresAt) {
				slog.Info("expiring demo", "slug", slug)
				_ = inst.cmd.Process.Kill()
				_ = inst.cmd.Wait()
				_ = os.RemoveAll(inst.dir)
				delete(r.instances, slug)
			}
		}
		r.mu.Unlock()
	}
}

func generateSlug() (string, error) {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i := range b {
		b[i] = chars[int(b[i])%len(chars)]
	}
	return string(b), nil
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

func waitForPort(port int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("localhost:%d", port), 200*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("port %d not ready after %s", port, timeout)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func expiredPage(w http.ResponseWriter, domain string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusGone)
	fmt.Fprintf(w, `<!doctype html>
<html>
<head><title>Demo Expired</title></head>
<body>
  <h1>This demo has expired</h1>
  <p>Demos are automatically cleaned up after 24 hours.</p>
  <p><a href="https://%s/launch">Start a new demo</a></p>
</body>
</html>`, domain)
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}
