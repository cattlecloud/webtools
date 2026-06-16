package webtools

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestCreateURL(t *testing.T) {
	t.Parallel()

	orig := "http://example.org:8000"
	params := map[string]string{
		"key":    "abc123",
		"offset": "3",
	}

	u := CreateURL(orig, "/hello", params)
	must.Eq(t, "http://example.org:8000/hello?key=abc123&offset=3", u.String())
}

func TestGetDomain(t *testing.T) {
	t.Parallel()

	orig := "http://stage.example.org/foo/bar"
	result := GetDomain(orig)
	must.Eq(t, "stage.example.org", result)
}

func Test_Sanitize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		exp   string
	}{
		{
			name:  "broken",
			input: "abc123",
			exp:   "abc123",
		},
		{
			name:  "simple",
			input: "https://example.org",
			exp:   "https://example.org",
		},
		{
			name:  "source",
			input: "https://example.org?utm_source=blah",
			exp:   "https://example.org",
		},
		{
			name:  "mix",
			input: "https://example.org?file=AA&utm_term=A",
			exp:   "https://example.org?file=AA",
		},
		{
			name:  "multiple",
			input: "https://example.org?utm_source=blah&file=AA&utm_content=none&page=2",
			exp:   "https://example.org?file=AA&page=2",
		},
		{
			name:  "social handle",
			input: "https://example.org?a=1&utm_social_handle_id=1847478489",
			exp:   "https://example.org?a=1",
		},
		{
			name:  "ad clicks",
			input: "https://example.org?gclid=abc123",
			exp:   "https://example.org",
		},
		{
			name:  "mailers",
			input: "https://example.org?mc_cid=abc234",
			exp:   "https://example.org",
		},
		{
			name:  "soc_src",
			input: "https://example.org?soc_src=123",
			exp:   "https://example.org",
		},
		{
			name:  "soc_trk",
			input: "https://example.org?soc_trk=reddit",
			exp:   "https://example.org",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := Sanitize(tc.input)
			must.Eq(t, tc.exp, result)
		})
	}
}
