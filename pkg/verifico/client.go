package verifico

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Config struct {
	Enabled bool
	Workers []string
	Secret  string
}

var (
	workers    []string
	secret     string
	httpClient *http.Client
	index      atomic.Uint64
)

func Init(cfg Config) {
	if !cfg.Enabled {
		workers = nil
		secret = ""
		httpClient = nil
		return
	}
	workers = cfg.Workers
	secret = cfg.Secret
	if len(workers) > 0 {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
}

func CompareHashAndPassword(hash, password []byte) error {
	if len(workers) == 0 {
		return bcrypt.CompareHashAndPassword(hash, password)
	}

	for range workers {
		i := index.Add(1) - 1
		worker := workers[i%uint64(len(workers))]

		match, err := callWorker(worker, hash, password)
		if err != nil {
			slog.Warn("verifico: worker failed, trying next", "worker", worker, "error", err)
			continue
		}
		if !match {
			return bcrypt.ErrMismatchedHashAndPassword
		}
		return nil
	}

	slog.Warn("verifico: all workers failed, falling back to local bcrypt")
	return bcrypt.CompareHashAndPassword(hash, password)
}

type WorkerStatus struct {
	Address     string
	Reachable   bool
	SecretValid bool
	Latency     time.Duration
	Error       string
}

func TestWorkers() []WorkerStatus {
	results := make([]WorkerStatus, len(workers))
	for i, w := range workers {
		results[i] = WorkerStatus{Address: w}

		// Connectivity check
		resp, err := httpClient.Get("http://" + w + "/healthz")
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			results[i].Error = fmt.Sprintf("healthz returned status %d", resp.StatusCode)
			continue
		}
		results[i].Reachable = true

		// Secret check
		start := time.Now()
		body, _ := json.Marshal(PingRequest{Secret: secret})
		resp, err = httpClient.Post("http://"+w+"/ping", "application/json", bytes.NewReader(body))
		results[i].Latency = time.Since(start)
		if err != nil {
			results[i].Error = err.Error()
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			results[i].Error = "secret mismatch"
			continue
		}
		if resp.StatusCode != http.StatusOK {
			results[i].Error = fmt.Sprintf("ping returned status %d", resp.StatusCode)
			continue
		}
		results[i].SecretValid = true
	}
	return results
}

func callWorker(worker string, hash, password []byte) (bool, error) {
	body, err := json.Marshal(VerifyRequest{
		Hash:     string(hash),
		Password: string(password),
		Secret:   secret,
	})
	if err != nil {
		return false, fmt.Errorf("marshal: %w", err)
	}

	resp, err := httpClient.Post("http://"+worker+"/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("status %d", resp.StatusCode)
	}

	var result VerifyResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decode: %w", err)
	}
	return result.Match, nil
}
