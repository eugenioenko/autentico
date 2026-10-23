package cli

import (
	"net/http"
	"time"
)

func newHTTPServer(addr string, handler http.Handler) *http.Server {
	// Bound incomplete requests and idle connections; allow larger admin exports
	// up to two minutes to finish writing their response.
	return &http.Server{
		Addr: addr, Handler: handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}
}
