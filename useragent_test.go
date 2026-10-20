package webtools

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mileusna/useragent"
	"github.com/shoenig/test/must"
)

func TestOrigin_From(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		forward string
		remote  string
		exp     string
	}{
		// From() is intentionally a simple "Forward ? Remote" pick; the
		// heavy lifting (port stripping, header cascade) lives in Origins()
		// and is exercised by TestOrigins_HeaderPrecedence.
		{"forward set", "10.0.0.1", "100.100.1.1", "10.0.0.1"},
		{"forward empty falls back to remote", "", "100.100.1.1", "100.100.1.1"},
		{"both empty", "", "", ""},
		{"forward already pre-parsed (chain)", "10.0.0.1", "100.100.1.1", "10.0.0.1"},
		{"forward already port-stripped", "10.0.0.1", "100.100.1.1:80", "10.0.0.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &Origin{
				Host:    "example.com",
				Forward: tc.forward,
				Remote:  tc.remote,
			}
			must.Eq(t, tc.exp, o.From())
		})
	}
}

func TestOrigin_Anchor(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		reference string
		exp       string
	}{
		{"Empty reference", "", "-"},
		{"Standard URL", "https://example.com/path/to/page", "example.com/path/to/page"},
		{"URL with query", "http://google.com/search?q=golang", "google.com/search"},
		{"URL with fragment", "https://github.com/mileusna/useragent#readme", "github.com/mileusna/useragent"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &Origin{Reference: tc.reference}
			must.Eq(t, tc.exp, o.Anchor())
		})
	}
}

func TestOrigin_String(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		userAgent useragent.UserAgent
		want      string
	}{
		{"Bot", useragent.UserAgent{Name: "Googlebot", Bot: true}, "Googlebot/bot"},
		{"Mobile", useragent.UserAgent{Name: "Safari", Mobile: true}, "Safari/phone"},
		{"Tablet", useragent.UserAgent{Name: "Chrome", Tablet: true}, "Chrome/tablet"},
		{"Desktop", useragent.UserAgent{Name: "Firefox", Desktop: true}, "Firefox/desktop"},
		{"Unknown", useragent.UserAgent{Name: "MyBrowser"}, "MyBrowser/unknown"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &Origin{UserAgent: tc.userAgent}
			must.Eq(t, tc.want, o.String())
		})
	}
}

func TestLeftmost(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{"empty", "", ""},
		{"single value", "10.0.0.1", "10.0.0.1"},
		{"single value with surrounding whitespace", "   10.0.0.1   ", "10.0.0.1"},
		{"chain", "10.0.0.1, 192.168.1.1, proxy.example.com", "10.0.0.1"},
		{"chain with whitespace", " 10.0.0.1 ,  192.168.1.1", "10.0.0.1"},
		{"only commas", ",,,", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			must.Eq(t, tc.expect, leftmost(tc.input))
		})
	}
}

func TestForwarded(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{"empty", "", ""},
		{"simple for=", "for=192.0.2.43", "192.0.2.43"},
		{"for with by and proto", "by=203.0.113.7;for=192.0.2.43;proto=https", "192.0.2.43"},
		{"proto before for", "proto=https;for=192.0.2.43", "192.0.2.43"},
		{"bracketed IPv6 quoted", `for="[2001:db8::1]:443";proto=https`, "2001:db8::1"},
		{"bracketed IPv6 quoted no port", `for="[2001:db8::1]"`, "2001:db8::1"},
		{"non-quoted v4 with port stripped", "for=192.0.2.43:443", "192.0.2.43"},
		{"multi-hop chain uses leftmost", "for=192.0.2.43, for=198.51.100.17", "192.0.2.43"},
		{"multi-entry leftmost wins", "for=192.0.2.43, by=10.0.0.5;for=198.51.100.17", "192.0.2.43"},
		{"redacted unknown falls through", "for=unknown", ""},
		{"redacted _hidden falls through", "for=_hidden", ""},
		{"redacted underscore-prefixed falls through", "for=_anything", ""},
		{"unknown falls through even with X-Real-IP style", "for=unknown  ;  proto=https", ""},
		{"for absent in entry", "by=203.0.113.7;proto=https", ""},
		{"only quotes stripped when no port", `for="10.0.0.1"`, "10.0.0.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			must.Eq(t, tc.expect, forwarded(tc.input))
		})
	}
}

func TestSanitize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  string
		expect string
	}{
		{"empty", "", ""},
		{"IPv4 with port", "198.51.100.7:54321", "198.51.100.7"},
		{"IPv4 without port", "198.51.100.7", "198.51.100.7"},
		{"bracketed IPv6 with port", "[2001:db8::1]:443", "2001:db8::1"},
		{"bracketed IPv6 without port", "[2001:db8::1]", "2001:db8::1"},
		{"bare IPv6 no port passes through", "::1", "::1"},
		{"hostname with port", "proxy.example.com:8443", "proxy.example.com"},
		{"hostname without port", "proxy.example.com", "proxy.example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			must.Eq(t, tc.expect, sanitize(tc.input))
		})
	}
}

func TestOrigins(t *testing.T) {
	t.Parallel()

	agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "https://example.org/v1/data", nil)
	r.Header.Set("X-Forwarded-For", "10.1.1.1")
	r.Header.Set("Referer", "https://dashboard.example.org/home")
	r.Header.Set("User-Agent", agent)

	origin := Origins(r)

	must.Eq(t, "POST", origin.Method)
	must.Eq(t, "example.org", origin.Host)
	must.Eq(t, "10.1.1.1", origin.Forward)
	must.Eq(t, "https://dashboard.example.org/home", origin.Reference)
	must.Eq(t, "Chrome", origin.UserAgent.Name)
}

// TestOrigins_HeaderPrecedence exercises the Forwarded -> X-Forwarded-For ->
// X-Real-IP -> RemoteAddr cascade against realistic header scenarios.
func TestOrigins_HeaderPrecedence(t *testing.T) {
	t.Parallel()

	type header struct {
		name, value string
	}

	cases := []struct {
		name        string
		headers     []header
		remoteAddr  string
		wantForward string
		wantRemote  string
		wantFrom    string
	}{
		{
			name: "Forwarded wins over XFF",
			headers: []header{
				{"Forwarded", "for=192.0.2.43"},
				{"X-Forwarded-For", "10.0.0.1"},
			},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "192.0.2.43",
			wantRemote:  "198.51.100.7",
			wantFrom:    "192.0.2.43",
		},
		{
			name: "Forwarded with bracket-quoted IPv6 wins",
			headers: []header{
				{"Forwarded", `for="[2001:db8::1]:443";proto=https`},
				{"X-Forwarded-For", "10.0.0.1"},
			},
			remoteAddr:  "[::1]:443",
			wantForward: "2001:db8::1",
			wantRemote:  "::1",
			wantFrom:    "2001:db8::1",
		},
		{
			name: "Forwarded redacted falls through to XFF",
			headers: []header{
				{"Forwarded", "for=_hidden"},
				{"X-Forwarded-For", "10.0.0.1, 192.168.1.1"},
			},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "10.0.0.1",
			wantRemote:  "198.51.100.7",
			wantFrom:    "10.0.0.1",
		},
		{
			name: "Forwarded unknown falls through to XFF",
			headers: []header{
				{"Forwarded", "for=unknown"},
				{"X-Forwarded-For", "10.0.0.1:8080"},
			},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "10.0.0.1",
			wantRemote:  "198.51.100.7",
			wantFrom:    "10.0.0.1",
		},
		{
			name: "Forwarded empty falls through to XFF",
			headers: []header{
				{"X-Forwarded-For", "10.0.0.1, 192.168.1.1, proxy.example.com"},
			},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "10.0.0.1",
			wantRemote:  "198.51.100.7",
			wantFrom:    "10.0.0.1",
		},
		{
			name:        "XFF absent, X-Real-IP used",
			headers:     []header{{"X-Real-IP", "10.42.42.42:8080"}},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "10.42.42.42",
			wantRemote:  "198.51.100.7",
			wantFrom:    "10.42.42.42",
		},
		{
			name:        "all headers absent, RemoteAddr used",
			headers:     nil,
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "",
			wantRemote:  "198.51.100.7",
			wantFrom:    "198.51.100.7",
		},
		{
			name:        "all empty, bare IPv6 remote",
			headers:     nil,
			remoteAddr:  "::1",
			wantForward: "",
			wantRemote:  "::1",
			wantFrom:    "::1",
		},
		{
			name:        "Forwarded malformed: only by/proto",
			headers:     []header{{"Forwarded", "by=203.0.113.7;proto=https"}},
			remoteAddr:  "198.51.100.7:54321",
			wantForward: "",
			wantRemote:  "198.51.100.7",
			wantFrom:    "198.51.100.7",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://example.org/", nil)
			r.RemoteAddr = tc.remoteAddr
			for _, h := range tc.headers {
				r.Header.Set(h.name, h.value)
			}
			o := Origins(r)
			must.Eq(t, tc.wantForward, o.Forward)
			must.Eq(t, tc.wantRemote, o.Remote)
			must.Eq(t, tc.wantFrom, o.From())
		})
	}
}
