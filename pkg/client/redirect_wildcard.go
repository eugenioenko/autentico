package client

import (
	"net/url"
	"strings"
)

// redirectWildcardParts validates the conformance-callback extension. Exact
// registration matching remains the default (RFC 6749 §3.1.2.3 / RFC 9700 §2.1).
// The extension permits one whole path segment and no fragment or traversal.
func redirectWildcardParts(pattern string) (prefix, suffix string, valid bool) {
	if strings.Count(pattern, "*") != 1 || strings.Contains(pattern, "#") {
		return "", "", false
	}
	parsed, err := url.Parse(pattern)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Opaque != "" {
		return "", "", false
	}
	// Check escaped parts so an encoded literal asterisk is not another wildcard.
	wholeSegment := false
	for _, part := range strings.Split(parsed.EscapedPath(), "/") {
		if part == "*" {
			wholeSegment = true
		}
	}
	if !wholeSegment || strings.Contains(parsed.Path, "\\") {
		return "", "", false
	}
	// RFC 3986 §5.2.4: browsers remove dot segments; never authorize through one.
	for _, part := range strings.Split(parsed.Path, "/") {
		if part == "." || part == ".." {
			return "", "", false
		}
	}
	index := strings.IndexByte(pattern, '*')
	return pattern[:index], pattern[index+1:], true
}

// matchesRedirectWildcard preserves every literal byte around one nonempty
// unreserved path component (RFC 3986 §2.3). It never decodes attacker input.
func matchesRedirectWildcard(pattern, candidate string) bool {
	prefix, suffix, valid := redirectWildcardParts(pattern)
	if !valid || !strings.HasPrefix(candidate, prefix) || !strings.HasSuffix(candidate, suffix) || len(candidate) < len(prefix)+len(suffix) {
		return false
	}
	segment := candidate[len(prefix) : len(candidate)-len(suffix)]
	if segment == "" || segment == "." || segment == ".." {
		return false
	}
	// Restrict the variable part to plain unreserved bytes: no path separators,
	// escaping (including repeated escaping), queries, fragments or controls.
	for _, char := range []byte(segment) {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || strings.ContainsRune("-._~", rune(char)) {
			continue
		}
		return false
	}
	return true
}
