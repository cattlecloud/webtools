package middles

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"cattlecloud.net/go/webtools/runtime"
	"github.com/shoenig/test/must"
)

func TestCache_ServeHTTP_local(t *testing.T) {
	t.Parallel()

	run := new(atomic.Bool)
	c := &CacheHTTP{
		Env: runtime.Setup(&runtime.Config{
			Environment: runtime.Local,
			Domain:      "example.com",
		}),
		H: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			run.Store(true)
		}),
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/abc.css", nil)
	c.ServeHTTP(w, r)

	must.Eq(t, 200, w.Code)
	must.True(t, run.Load())
	must.Eq(t, "private, max-age=5", w.Header().Get("Cache-Control"))
}

func TestCache_ServeHTTP_staging_css(t *testing.T) {
	t.Parallel()

	run := new(atomic.Bool)
	c := &CacheHTTP{
		Env: runtime.Setup(&runtime.Config{
			Environment: runtime.Staging,
			Domain:      "example.com",
		}),
		H: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			run.Store(true)
		}),
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/abc.css", nil)
	c.ServeHTTP(w, r)

	must.Eq(t, 200, w.Code)
	must.True(t, run.Load())
	must.Eq(t, "private, max-age=60", w.Header().Get("Cache-Control"))
}

func TestCache_ServeHTTP_staging_txt(t *testing.T) {
	t.Parallel()

	run := new(atomic.Bool)
	c := &CacheHTTP{
		Env: runtime.Setup(&runtime.Config{
			Environment: runtime.Staging,
			Domain:      "example.com",
		}),
		H: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			run.Store(true)
		}),
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/abc.txt", nil)
	c.ServeHTTP(w, r)

	must.Eq(t, 200, w.Code)
	must.True(t, run.Load())
	must.Eq(t, "private, max-age=3600", w.Header().Get("Cache-Control"))
}

func TestCache_ServeHTTP_production_css(t *testing.T) {
	t.Parallel()

	run := new(atomic.Bool)
	c := &CacheHTTP{
		Env: runtime.Setup(&runtime.Config{
			Environment: runtime.Production,
			Domain:      "example.com",
		}),
		H: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			run.Store(true)
		}),
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/abc.css", nil)
	c.ServeHTTP(w, r)

	must.Eq(t, 200, w.Code)
	must.True(t, run.Load())
	must.Eq(t, "private, max-age=10800", w.Header().Get("Cache-Control"))
}

func TestCache_ServeHTTP_production_txt(t *testing.T) {
	t.Parallel()

	run := new(atomic.Bool)
	c := &CacheHTTP{
		Env: runtime.Setup(&runtime.Config{
			Environment: runtime.Production,
			Domain:      "example.com",
		}),
		H: http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
			run.Store(true)
		}),
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "/abc.txt", nil)
	c.ServeHTTP(w, r)

	must.Eq(t, 200, w.Code)
	must.True(t, run.Load())
	must.Eq(t, "private, max-age=86400", w.Header().Get("Cache-Control"))
}
