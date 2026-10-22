package federation

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestIsPrivateIP covers address families, mapped forms and metadata address space.
func TestIsPrivateIP(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.100.100.200", "100.64.0.1", "100.127.255.254", "0.0.0.0", "0.1.2.3", "224.0.0.1", "255.255.255.255", "::", "::1", "fc00::1", "fd00:ec2::254", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254", "invalid"} {
		require.True(t, isPrivateIP(net.ParseIP(ip)), ip)
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "100.63.255.255", "100.128.0.1", "93.184.216.34", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		require.False(t, isPrivateIP(net.ParseIP(ip)), ip)
		require.NoError(t, checkFederationAddress("tcp", net.JoinHostPort(ip, "443"), nil))
	}
	for _, address := range []string{"bad", "unresolved.example:443", "127.0.0.1:80", "[fe80::1%eth0]:80", "[::ffff:127.0.0.1]:80"} {
		require.Error(t, checkFederationAddress("tcp", address, nil), address)
	}
}

// TestSafeHTTPClientBlocksInitialConnections proves rejection occurs before HTTP reaches a trap.
func TestSafeHTTPClientBlocksInitialConnections(t *testing.T) {
	var requests atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(200) }))
	defer trap.Close()
	u, err := url.Parse(trap.URL)
	require.NoError(t, err)
	client := safeHTTPClient()
	defer client.CloseIdleConnections()
	for _, host := range []string{"127.0.0.1", "localhost", "::ffff:127.0.0.1"} {
		resp, err := client.Get("http://" + net.JoinHostPort(host, u.Port()))
		require.ErrorContains(t, err, "private IP", host)
		require.Nil(t, resp)
	}
	require.Zero(t, requests.Load())
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err == nil {
		v6 := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { requests.Add(1); w.WriteHeader(200) }))
		_ = v6.Listener.Close()
		v6.Listener = listener
		v6.Start()
		defer v6.Close()
		_, err = client.Get(v6.URL)
		require.ErrorContains(t, err, "private IP")
		require.Zero(t, requests.Load())
	}
}

type federationRoundTripFunc func(*http.Request) (*http.Response, error)

// RoundTrip provides deterministic provider responses without public network access.
func (f federationRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// federationResponse constructs a complete response for a synthetic public endpoint.
func federationResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

// TestSafeHTTPClientRedirects separates redirect policy from the guarded network hop.
func TestSafeHTTPClientRedirects(t *testing.T) {
	var reached atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
	defer trap.Close()
	t.Run("private destination", func(t *testing.T) {
		client := safeHTTPClient()
		transport := client.Transport
		defer transport.(*http.Transport).CloseIdleConnections()
		client.Transport = federationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == "public.example" {
				resp := federationResponse(r, 302, "")
				resp.Header.Set("Location", trap.URL)
				return resp, nil
			}
			return transport.RoundTrip(r)
		})
		_, err := client.Get("https://public.example/start")
		require.ErrorContains(t, err, "private IP")
		require.Zero(t, reached.Load())
	})
	t.Run("public destination", func(t *testing.T) {
		client := safeHTTPClient()
		client.Transport = federationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/done" {
				return federationResponse(r, 200, "ok"), nil
			}
			resp := federationResponse(r, 302, "")
			resp.Header.Set("Location", "https://other-public.example/done")
			return resp, nil
		})
		resp, err := client.Get("https://public.example/start")
		require.NoError(t, err)
		_ = resp.Body.Close()
		require.Equal(t, 200, resp.StatusCode)
	})
	t.Run("redirect limit", func(t *testing.T) {
		client := safeHTTPClient()
		var requests int
		client.Transport = federationRoundTripFunc(func(r *http.Request) (*http.Response, error) {
			requests++
			resp := federationResponse(r, 302, "")
			resp.Header.Set("Location", "https://public.example/loop")
			return resp, nil
		})
		resp, err := client.Get("https://public.example/start")
		require.ErrorContains(t, err, "too many redirects")
		if resp != nil {
			_ = resp.Body.Close()
		}
		require.Equal(t, 5, requests)
	})
}

// TestSafeHTTPClientDNSRebinding changes DNS after a successful public precheck.
func TestSafeHTTPClientDNSRebinding(t *testing.T) {
	var private atomic.Bool
	resolver := rebindResolver(t, &private)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip4", "rebind.test")
	require.NoError(t, err)
	require.Len(t, ips, 1)
	require.False(t, isPrivateIP(ips[0]))
	private.Store(true)
	var reached atomic.Int32
	trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
	defer trap.Close()
	u, err := url.Parse(trap.URL)
	require.NoError(t, err)
	client := safeHTTPClient()
	defer client.CloseIdleConnections()
	dialer := federationDialer()
	dialer.Resolver = resolver
	client.Transport.(*http.Transport).DialContext = dialer.DialContext
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://rebind.test:"+u.Port(), nil)
	require.NoError(t, err)
	_, err = client.Do(req)
	require.ErrorContains(t, err, "private IP")
	require.Zero(t, reached.Load(), "a stale public DNS precheck cannot authorize a private connection")
}

// rebindResolver switches an A record from public to private between lookups.
func rebindResolver(t *testing.T, private *atomic.Bool) *net.Resolver {
	return federationDNSResolver(t, func(qtype uint16) []net.IP {
		if qtype != 1 {
			return nil
		}
		if private.Load() {
			return []net.IP{net.ParseIP("127.0.0.1")}
		}
		return []net.IP{net.ParseIP("8.8.8.8")}
	})
}

// TestSafeHTTPClientCandidateFallback guards every candidate without external connections.
func TestSafeHTTPClientCandidateFallback(t *testing.T) {
	for _, dualStack := range []bool{false, true} {
		name := "IPv4 candidates"
		if dualStack {
			name = "public IPv6 failure before private IPv4 fallback"
		}
		t.Run(name, func(t *testing.T) {
			if dualStack {
				listener, err := net.Listen("tcp6", "[::1]:0")
				if err != nil {
					t.Skip("IPv6 sockets unavailable")
				}
				_ = listener.Close()
			}
			var reached atomic.Int32
			trap := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { reached.Add(1); w.WriteHeader(200) }))
			defer trap.Close()
			u, err := url.Parse(trap.URL)
			require.NoError(t, err)
			resolver := federationDNSResolver(t, func(qtype uint16) []net.IP {
				if dualStack {
					if qtype == 28 {
						return []net.IP{net.ParseIP("2606:4700:4700::1111")}
					}
					if qtype == 1 {
						return []net.IP{net.ParseIP("127.0.0.1")}
					}
				} else if qtype == 1 {
					return []net.IP{net.ParseIP("8.8.8.8"), net.ParseIP("127.0.0.1")}
				}
				return nil
			})
			client := safeHTTPClient()
			defer client.CloseIdleConnections()
			dialer := federationDialer()
			dialer.Resolver = resolver
			dialer.FallbackDelay = time.Millisecond
			control := dialer.Control
			require.NotNil(t, control)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var mu sync.Mutex
			var attempts []string
			publicFailed := make(chan struct{})
			var once sync.Once
			dialer.Control = func(network, address string, raw syscall.RawConn) error {
				host, _, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				private := isPrivateIP(net.ParseIP(host))
				// RFC 6724 may sort the private IPv4 address first on an IPv4-only
				// host. Hold that attempt until the real dual-stack dialer's public
				// candidate fails, keeping the validation sequence deterministic.
				if dualStack && private {
					select {
					case <-publicFailed:
					case <-ctx.Done():
						return ctx.Err()
					}
				}
				label := "public"
				if private {
					label = "private"
				}
				mu.Lock()
				attempts = append(attempts, label)
				mu.Unlock()
				if err := control(network, address, raw); err != nil {
					return err
				}
				if private {
					// A broken guard must reach the trap so this test fails.
					return nil
				}
				// Fail the allowed public candidate before connect; tests never send
				// traffic to the public network, then exercise the next real candidate.
				once.Do(func() { close(publicFailed) })
				return errors.New("synthetic public connection failure")
			}
			client.Transport.(*http.Transport).DialContext = dialer.DialContext
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://fallback.test:"+u.Port(), nil)
			require.NoError(t, err)
			resp, err := client.Do(req)
			if resp != nil {
				_ = resp.Body.Close()
			}
			require.Error(t, err)
			mu.Lock()
			got := append([]string(nil), attempts...)
			mu.Unlock()
			require.ElementsMatch(t, []string{"public", "private"}, got)
			if dualStack {
				require.Equal(t, []string{"public", "private"}, got)
			}
			require.Zero(t, reached.Load(), "a failed public candidate must not authorize a private fallback")
		})
	}
}

// federationDNSResolver serves minimal zero-TTL A/AAAA replies, including multiple candidates.
func federationDNSResolver(t *testing.T, answers func(uint16) []net.IP) *net.Resolver {
	t.Helper()
	server, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			n, peer, err := server.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 17 {
				continue
			}
			i := 12
			for i < n && buf[i] != 0 {
				i += int(buf[i]) + 1
			}
			if i+5 > n {
				continue
			}
			qtype := binary.BigEndian.Uint16(buf[i+1 : i+3])
			records := answers(qtype)
			response := append([]byte(nil), buf[:i+5]...)
			binary.BigEndian.PutUint16(response[2:4], 0x8180)
			for k := 6; k < 12; k++ {
				response[k] = 0
			}
			binary.BigEndian.PutUint16(response[6:8], uint16(len(records)))
			for _, ip := range records {
				data := ip.To16()
				if qtype == 1 {
					data = ip.To4()
				}
				response = append(response, 0xc0, 0x0c, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 0, 0, byte(len(data)))
				response = append(response, data...)
			}
			_, _ = server.WriteTo(response, peer)
		}
	}()
	t.Cleanup(func() { _ = server.Close(); <-done })
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "udp", server.LocalAddr().String())
	}}
}
