package verifico

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/crypto/bcrypt"
)

type VerifyRequest struct {
	Hash     string `json:"hash"`
	Password string `json:"password"`
	Secret   string `json:"secret"`
}

type VerifyResponse struct {
	Match bool `json:"match"`
}

func HandleVerify(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		err := bcrypt.CompareHashAndPassword([]byte(req.Hash), []byte(req.Password))
		resp := VerifyResponse{Match: err == nil}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

type PingRequest struct {
	Secret string `json:"secret"`
}

func HandlePing(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var req PingRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}

		if subtle.ConstantTimeCompare([]byte(req.Secret), []byte(secret)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func RunWorkerServer(port, secret string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", HandleVerify(secret))
	mux.HandleFunc("POST /ping", HandlePing(secret))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("verifico: shutdown error: %v", err)
		}
	}()

	fmt.Println()
	fmt.Printf("  Verifico worker listening on :%s\n", port)
	fmt.Println()

	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
