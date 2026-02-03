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
