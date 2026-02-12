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
			must.Eq(t, tc.exp, o.From())
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

func TestOrigins(t *testing.T) {
	t.Parallel()

	agent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
	r := httptest.NewRequest(http.MethodPost, "https://example.org/v1/data", nil)
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
