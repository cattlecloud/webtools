package webtools

import (
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/mileusna/useragent"
)

// Origin contins request origination context from parsing request headers.
type Origin struct {
	// about the request
	Method    string
	Host      string
	UserAgent useragent.UserAgent

	// about the requesting entity
	//
	// Forward is the originating client as derived from the X-Forwarded-For,
	// RFC 7239 Forwarded, or X-Real-IP headers (consulted in that order).
	// It is the leftmost usable entry with any port stripped. The value
	// is a bare host with no port.
	//
	// Remote is the host portion of the TCP source address (r.RemoteAddr)
	// with any port stripped.
	Forward   string
	Remote    string
	Reference string
}

// From returns the originating client IP. If available, this is the
// leftmost usable value from the Forwarded (RFC 7239), X-Forwarded-For,
// or X-Real-IP headers, in that order. Otherwise it falls back to the
// host portion of RemoteAddr. Ports are always stripped.
func (o *Origin) From() string {
	if o.Forward != "" {
		return o.Forward
	}
	return o.Remote
}

// Anchor returns a parsed version of the Referer headers, including the domain
// and path without the protocol or query.
func (o *Origin) Anchor() string {
	if o.Reference == "" {
		return "-"
	}

	u, _ := url.Parse(o.Reference)
	return u.Host + u.Path
}

// String returns the parsed user agent, including only the name and type of
// device being used (or bot).
func (o *Origin) String() string {
	var mode string
	switch {
	case o.UserAgent.Bot:
		mode = "bot"
	case o.UserAgent.Mobile:
		mode = "phone"
	case o.UserAgent.Tablet:
		mode = "tablet"
	case o.UserAgent.Desktop:
		mode = "desktop"
	default:
		mode = "unknown"
	}
	return o.UserAgent.Name + "/" + mode
}

// Origins parses the request headers to get information about the origins of
// the request, including ...
//
// - Method
// - Host
// - Referer
// - User-Agent
//
// The originating client IP (Forward/Remote) is resolved from headers in this
// order:
//
//  1. Forwarded (RFC 7239) — leftmost usable "for=" value, with quotes and
//     port stripped; redacted values ("unknown", "_hidden", any value
//     starting with "_") are treated as missing.
//  2. X-Forwarded-For — leftmost comma-separated entry, port stripped.
//  3. X-Real-IP — common nginx convention, port stripped.
//  4. RemoteAddr — host portion of the TCP source address, port stripped.
//
// Ports are always stripped regardless of source.
func Origins(r *http.Request) *Origin {
	method := strings.ToUpper(r.Method)
	host := r.Host
	remote := sanitize(r.RemoteAddr)
	forward := forwarded(r.Header.Get("Forwarded"))
	if forward == "" {
		forward = sanitize(leftmost(r.Header.Get("X-Forwarded-For")))
	}
	if forward == "" {
		forward = sanitize(r.Header.Get("X-Real-IP"))
	}
	reference := r.Header.Get("Referer")
	agent := r.Header.Get("User-Agent")
	ua := useragent.Parse(agent)
	return &Origin{
		Method:    method,
		Host:      host,
		UserAgent: ua,
		Forward:   forward,
		Remote:    remote,
		Reference: reference,
	}
}

// leftmost returns the first comma-separated token of a header value with
// surrounding whitespace stripped, or "" when the input is empty.
func leftmost(header string) string {
	if i := strings.Index(header, ","); i >= 0 {
		header = header[:i]
	}
	return strings.TrimSpace(header)
}

// forwarded parses an RFC 7239 Forwarded header and returns the leftmost
// usable "for=" value with surrounding quotes and any port stripped. It
// returns "" when the header is absent, malformed, or contains only
// redacted values (the literal "unknown" or any value beginning with "_").
func forwarded(header string) string {
	if header == "" {
		return ""
	}
	for _, entry := range strings.Split(header, ",") {
		entry = strings.TrimSpace(entry)
		var value string
		var found bool
		for _, param := range strings.Split(entry, ";") {
			param = strings.TrimSpace(param)
			if !strings.HasPrefix(param, "for=") {
				continue
			}
			value = strings.TrimPrefix(param, "for=")
			found = true
			break
		}
		if !found {
			continue
		}
		// Strip surrounding double quotes, per RFC 7239.
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = value[1 : len(value)-1]
		}
		// Treat redacted tokens as missing so callers transparently fall
		// through to the next source (X-Forwarded-For, X-Real-IP, RemoteAddr).
		if value == "unknown" || strings.HasPrefix(value, "_") {
			continue
		}
		return sanitize(value)
	}
	return ""
}

// sanitize returns the host portion of an address, stripping any trailing
// port. It accepts "host:port", "[ipv6]:port", and bare bracketed IPv6
// addresses. If no port can be detected the input is returned unchanged.
func sanitize(address string) string {
	if address == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(address); err == nil {
		return host
	}
	// Bare bracketed IPv6, e.g. "[2001:db8::1]" with no port.
	if len(address) >= 2 && address[0] == '[' && address[len(address)-1] == ']' {
		return address[1 : len(address)-1]
	}
	return address
}
