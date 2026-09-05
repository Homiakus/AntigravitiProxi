package diagnostics

import (
	"net"
	"regexp"
	"strings"
)

var (
	redactBearer = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{12,}`)
	redactToken  = regexp.MustCompile(`(?i)("?(?:access_token|refresh_token|id_token|authorization|cookie)"?\s*[:=]\s*"?)[^"\s,}]+`)
	redactEmail  = regexp.MustCompile(`(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b`)
	redactPath   = regexp.MustCompile(`(?i)(?:/home/[^\s"']+|/Users/[^\s"']+|[A-Z]:\\Users\\[^\s"']+)`)
)

// Redact applies the same conservative export policy to diagnostic text and
// support-facing snapshots. It is intentionally deterministic and leaves
// protocol labels intact while removing credential, identity and address data.
func Redact(value string) string {
	value = redactBearer.ReplaceAllString(value, "Bearer <redacted>")
	value = redactToken.ReplaceAllString(value, `${1}<redacted>`)
	value = redactEmail.ReplaceAllString(value, "<email-redacted>")
	value = redactPath.ReplaceAllString(value, "<path-redacted>")
	for _, field := range strings.FieldsFunc(value, func(r rune) bool { return r == ' ' || r == ',' || r == ';' || r == '[' || r == ']' }) {
		if ip := net.ParseIP(strings.Trim(field, "()\"")); ip != nil {
			value = strings.ReplaceAll(value, field, "<ip-redacted>")
		}
	}
	return value
}
