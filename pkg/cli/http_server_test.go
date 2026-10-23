package cli

import (
	"bufio"
	"errors"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func socketTestServer(t *testing.T, handler http.Handler) (*http.Server, string) {
	t.Helper()
	srv := newHTTPServer("127.0.0.1:0", handler)
	// Exercise the production configuration with shorter deadlines. A missing
	// timeout remains zero and fails the real socket tests instead of hanging.
	require.Greater(t, srv.ReadHeaderTimeout, time.Duration(0))
	require.Greater(t, srv.ReadTimeout, srv.ReadHeaderTimeout)
	require.Greater(t, srv.WriteTimeout, srv.ReadTimeout)
	require.Greater(t, srv.IdleTimeout, time.Duration(0))
	srv.ReadHeaderTimeout /= 100
	srv.ReadTimeout /= 100
	srv.WriteTimeout /= 100
	srv.IdleTimeout /= 100
	listener, err := net.Listen("tcp", srv.Addr)
	require.NoError(t, err)
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	t.Cleanup(func() { require.NoError(t, srv.Close()); require.ErrorIs(t, <-done, http.ErrServerClosed) })
	return srv, listener.Addr().String()
}

func dialDeadline(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	return conn
}

func TestHTTPServerClosesPartialHeaders(t *testing.T) {
	_, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("incomplete request reached handler") }))
	conn := dialDeadline(t, addr)
	_, err := io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Slow: ")
	require.NoError(t, err)
	_, err = bufio.NewReader(conn).ReadByte()
	require.Error(t, err)
	if e, ok := err.(net.Error); ok {
		require.False(t, e.Timeout(), "server left partial headers open")
	}
}

func TestHTTPServerClosesSlowRequestBody(t *testing.T) {
	_, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			http.Error(w, "incomplete body", http.StatusRequestTimeout)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	conn := dialDeadline(t, addr)
	_, err := io.WriteString(conn, "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nx")
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusRequestTimeout, resp.StatusCode)
	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	_, err = reader.ReadByte()
	require.Error(t, err)
	if e, ok := err.(net.Error); ok {
		require.False(t, e.Timeout(), "slow-body connection was not closed")
	}

}

func TestHTTPServerClosesIdleKeepAlive(t *testing.T) {
	_, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "healthy") }))
	conn := dialDeadline(t, addr)
	_, err := io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "healthy", string(body))
	_, err = reader.ReadByte()
	require.Error(t, err)
	if e, ok := err.(net.Error); ok {
		require.False(t, e.Timeout(), "server left idle connection open")
	}
}

func TestHTTPServerAllowsResponseAfterReadDeadline(t *testing.T) {
	srv, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(450 * time.Millisecond)
		_, _ = io.WriteString(w, strings.Repeat("export-data", 10000))
	}))
	require.Less(t, srv.ReadTimeout, 450*time.Millisecond)
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	for _, path := range []string{"/healthz", "/admin/api/settings/export"} {
		resp, err := client.Get("http://" + addr + path)
		require.NoError(t, err)
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Equal(t, strings.Repeat("export-data", 10000), string(body))
	}
}

func TestHTTPServerBoundsResponseWrites(t *testing.T) {
	srv, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1400 * time.Millisecond)
		_, _ = io.WriteString(w, "too late")
	}))
	require.Less(t, srv.WriteTimeout, 1400*time.Millisecond)
	client := &http.Client{Timeout: 5 * time.Second}
	defer client.CloseIdleConnections()
	resp, err := client.Get("http://" + addr + "/slow")
	if resp != nil {
		_ = resp.Body.Close()
	}
	require.Error(t, err)
}

func TestHTTPServerTimesOutBlockedSocketWrites(t *testing.T) {
	result := make(chan error, 1)
	_, addr := socketTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		payload := strings.Repeat("x", 64*1024)
		for {
			if _, err := io.WriteString(w, payload); err != nil {
				result <- err
				return
			}
		}
	}))
	conn := dialDeadline(t, addr)
	tcp, ok := conn.(*net.TCPConn)
	require.True(t, ok)
	require.NoError(t, tcp.SetReadBuffer(1024))
	_, err := io.WriteString(conn, "GET /large-export HTTP/1.1\r\nHost: localhost\r\n\r\n")
	require.NoError(t, err)
	// Do not read: the response must fill the socket buffers and then time out.
	select {
	case err := <-result:
		var networkError net.Error
		require.True(t, errors.As(err, &networkError))
		require.True(t, networkError.Timeout())
	case <-time.After(4 * time.Second):
		t.Fatal("blocked response write did not time out")
	}
}
