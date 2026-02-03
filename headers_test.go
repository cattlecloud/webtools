package webtools

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cattlecloud.net/go/scope"
	"github.com/shoenig/test/must"
)

func Test_SetCacheControl(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	SetCacheControl(w, 4*time.Minute)
	must.Eq(t, "private, max-age=240", w.Header().Get("Cache-Control"))
}

func Test_SetContentType(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	SetContentType(w, ContentTypeText)
	must.Eq(t, "text/plain; charset=utf8", w.Header().Get("Content-Type"))
}

func Test_SetBasicAuth(t *testing.T) {
	t.Parallel()

	r, err := http.NewRequestWithContext(scope.New(), http.MethodGet, "/", nil)
	must.NoError(t, err)
	SetBasicAuth(r, "bob", "passw0rd")

	value := r.Header.Get("Authorization")
	must.Eq(t, "Basic Ym9iOnBhc3N3MHJk", value)
}

func Test_SetBasicAuth_empty(t *testing.T) {
	t.Parallel()

	r, err := http.NewRequestWithContext(scope.New(), http.MethodGet, "/", nil)
	must.NoError(t, err)
	SetBasicAuth(r, "bob", "")

	value := r.Header.Get("Authorization")
	must.Eq(t, "", value) // not set
}
