// Package sqliteutil builds SQLite file URIs without treating drive letters as hosts.
package sqliteutil

import (
	"net/url"
	"path/filepath"
)

// FileURL escapes reserved characters and keeps Windows drive and UNC paths in
// the URI path. SQLite rejects authorities other than empty or localhost.
func FileURL(path string) url.URL {
	if path == ":memory:" {
		return url.URL{Scheme: "file", Opaque: ":memory:"}
	}
	path = filepath.ToSlash(path)
	if len(path) >= 3 && path[1] == ':' && path[2] == '/' {
		path = "/" + path
	}
	return url.URL{Scheme: "file", Path: path}
}
