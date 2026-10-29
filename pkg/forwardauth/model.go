// Package forwardauth implements proxy authentication using app-scoped browser
// credentials linked to existing IdP sessions. It does not forward app traffic.
package forwardauth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/eugenioenko/autentico/pkg/config"
	"golang.org/x/net/publicsuffix"
)

type App struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Origin             string   `json:"origin"`
	AllowedReturnPaths []string `json:"allowed_return_paths"`
	ClientID           string   `json:"client_id"`
	SessionTTL         string   `json:"session_ttl"`
	IsActive           bool     `json:"is_active"`
}

// AppRequest is used for creation and full replacement. Origin is immutable.
type AppRequest struct {
	Name               string   `json:"name"`
	Origin             string   `json:"origin"`
	AllowedReturnPaths []string `json:"allowed_return_paths"`
	SessionTTL         string   `json:"session_ttl"`
	IsActive           *bool    `json:"is_active"`
}

func (a App) route(action string) string { return "/_autentico/" + a.ID + "/" + action }
func (a App) callback() string           { return a.Origin + a.route("callback") }
func (a App) secure() bool               { return strings.HasPrefix(a.Origin, "https://") }
func (a App) cookieName() string {
	prefix := ""
	if a.secure() {
		prefix = "__Host-"
	}
	return prefix + "autentico_fa_" + a.ID
}

// canonicalPath rejects ambiguous paths before segment-aware prefix matching.
// RFC 3986 §5.2.4 / RFC 9700 §4.11: normalization must not escape an allowlist.
func canonicalPath(raw string) (string, error) {
	u, err := url.ParseRequestURI(raw)
	if err != nil || u.IsAbs() || u.Host != "" || u.Fragment != "" || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || len(raw) > 4096 {
		return "", fmt.Errorf("expected a local absolute path")
	}
	p := u.Path
	// RFC 3986 §3.3 leaves path-parameter interpretation to applications.
	// Reject decoded semicolons so downstream routers cannot turn "..;" into
	// traversal after this allowlist has already approved a request.
	if strings.ContainsAny(p, "\\\r\n\x00%;") || strings.Contains(p, "//") || strings.ContainsAny(u.RawQuery, "\r\n\x00") || strings.Contains(raw, "#") {
		return "", fmt.Errorf("ambiguous path")
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "." || segment == ".." {
			return "", fmt.Errorf("dot segments are not allowed")
		}
	}
	if p == "/_autentico" || strings.HasPrefix(p, "/_autentico/") {
		return "", fmt.Errorf("reserved authentication path")
	}
	return p, nil
}

func (a App) allowReturn(raw string) bool {
	p, err := canonicalPath(raw)
	if err != nil {
		return false
	}
	for _, prefix := range a.AllowedReturnPaths {
		if prefix == "/" || p == prefix || strings.HasPrefix(p, prefix+"/") {
			return true
		}
	}
	return false
}

func site(host string) string {
	if net.ParseIP(host) != nil || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return host
	}
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return domain
}

func validate(req *AppRequest) error {
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > 100 || strings.ContainsAny(req.Name, "<>\r\n") {
		return fmt.Errorf("name must contain 1–100 plain text characters")
	}
	u, err := url.Parse(req.Origin)
	bs, bsErr := url.Parse(config.GetBootstrap().AppURL)
	// RFC 9700 §2.1 / §4.11: exact registered origins, same-site only in v1.
	if err != nil || bsErr != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || strings.ContainsAny(u.Host, "%,\\\t\r\n ") || strings.Contains(req.Origin, "#") {
		return fmt.Errorf("origin must be an absolute HTTP(S) origin without credentials, path, query or fragment")
	}
	hostname := strings.ToLower(u.Hostname())
	if net.ParseIP(hostname) == nil && !validHostname(hostname) {
		return fmt.Errorf("invalid hostname; use ASCII or punycode DNS names")
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return fmt.Errorf("invalid origin port")
	}
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	u.Host = hostname
	if strings.Contains(hostname, ":") {
		u.Host = "[" + hostname + "]"
	}
	if port != "" {
		u.Host = net.JoinHostPort(hostname, port)
	}
	u.Path = ""
	local := u.Hostname() == "localhost" || net.ParseIP(u.Hostname()) != nil && net.ParseIP(u.Hostname()).IsLoopback()
	if u.Scheme != "https" && (u.Scheme != "http" || !local) {
		return fmt.Errorf("HTTPS is required except on loopback")
	}
	// RFC 6265 §8.5: cookies do not isolate ports. Production app hosts
	// must differ from the IdP host so its cookie never reaches the app proxy.
	if !local && u.Hostname() == strings.ToLower(bs.Hostname()) {
		return fmt.Errorf("application hostname must differ from Autentico's hostname")
	}
	if u.Scheme != bs.Scheme || site(u.Hostname()) != site(strings.ToLower(bs.Hostname())) || u.Host == strings.ToLower(bs.Host) {
		return fmt.Errorf("app must have a distinct origin on the same schemeful site as Autentico")
	}
	if port := u.Port(); port != "" {
		if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
			return fmt.Errorf("invalid origin port")
		}
	}
	req.Origin = u.String()
	if len(req.AllowedReturnPaths) == 0 || len(req.AllowedReturnPaths) > 32 {
		return fmt.Errorf("provide 1–32 allowed path prefixes")
	}
	for _, prefix := range req.AllowedReturnPaths {
		p, err := canonicalPath(prefix)
		if err != nil || p != prefix || path.Clean(prefix) != prefix {
			return fmt.Errorf("allowed paths must be canonical path prefixes without queries or trailing slashes")
		}
	}
	if req.SessionTTL == "" {
		req.SessionTTL = "8h"
	}
	ttl, err := time.ParseDuration(req.SessionTTL)
	if err != nil || ttl < time.Second || ttl > 24*time.Hour {
		return fmt.Errorf("session_ttl must be between 1s and 24h")
	}
	return nil
}

func pathsJSON(paths []string) string { b, _ := json.Marshal(paths); return string(b) }

// DNS authorities are stored in the browser's ASCII form. Reject unusable
// registrations rather than accepting a hostname the browser will rewrite.
func validHostname(host string) bool {
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if c != '-' && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
				return false
			}
		}
	}
	return true
}

// validStored rechecks current policy only where a registration authenticates
// traffic. Admin reads/deletes must also work after a deployment moves sites.
func (a *App) validStored() bool {
	req := AppRequest{Name: a.Name, Origin: a.Origin, AllowedReturnPaths: a.AllowedReturnPaths, SessionTTL: a.SessionTTL}
	return validate(&req) == nil && req.Origin == a.Origin && req.SessionTTL == a.SessionTTL
}
