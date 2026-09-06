package diagnostics

import (
	"net"
	"regexp"
	"strings"
)

var (
	redactBearer      = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}`)
	redactToken       = regexp.MustCompile(`(?i)("?(?:access_token|refresh_token|id_token|authorization|cookie)"?\s*[:=]\s*"?)[^"\s,}]+`)
	redactEmail       = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	redactPath        = regexp.MustCompile(`(?i)(?:/home/[^\s"']+|/Users/[^\s"']+|[A-Z]:\\Users\\[^\s"']+)`)
	redactIPv4        = regexp.MustCompile(`\b((?:\d{1,3}\.){3}\d{1,3})(?::\d{1,5})?\b`)
	redactIPv6Bracket = regexp.MustCompile(`\[([0-9a-fA-F:]+)\](?::\d{1,5})?`)
)

// Redact applies the same conservative export policy to diagnostic text and
// support-facing snapshots. It is intentionally deterministic and leaves
// protocol labels intact while removing credential, identity and address data.
func Redact(value string) string {
	value = redactBearer.ReplaceAllString(value, "Bearer <redacted>")
	value = redactToken.ReplaceAllString(value, `${1}<redacted>`)
	value = redactEmail.ReplaceAllString(value, "<email-redacted>")
	value = redactPath.ReplaceAllString(value, "<path-redacted>")
	value = redactIPv4.ReplaceAllStringFunc(value, func(m string) string {
		sub := redactIPv4.FindStringSubmatch(m)
		if len(sub) > 1 && net.ParseIP(sub[1]) != nil {
			return "<ip-redacted>"
		}
		return m
	})
	value = redactIPv6Bracket.ReplaceAllStringFunc(value, func(m string) string {
		sub := redactIPv6Bracket.FindStringSubmatch(m)
		if len(sub) > 1 && net.ParseIP(sub[1]) != nil {
			return "<ip-redacted>"
		}
		return m
	})
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' || r == '[' || r == ']' }) {
		trimmed := strings.Trim(field, "()\"'")
		if ip := net.ParseIP(trimmed); ip != nil {
			value = strings.ReplaceAll(value, field, "<ip-redacted>")
			continue
		}
		if _, _, err := net.ParseCIDR(trimmed); err == nil {
			value = strings.ReplaceAll(value, field, "<ip-redacted>")
			continue
		}
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			host = strings.Trim(host, "[]")
			if ip := net.ParseIP(host); ip != nil {
				value = strings.ReplaceAll(value, field, "<ip-redacted>")
			}
		}
	}
	return value
}
