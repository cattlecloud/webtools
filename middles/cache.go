package middles

import (
	"net/http"
	"strings"
	"time"

	"cattlecloud.net/go/webtools"
	"cattlecloud.net/go/webtools/runtime"
	"github.com/shoenig/lang"
)

type CacheHTTP struct {
	Env runtime.Environment
	H   http.Handler
}

func (c *CacheHTTP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var ttl time.Duration

	switch c.Env.String() {
	case runtime.Local:
		ttl = 5 * time.Second

	case runtime.Staging:
		css := strings.HasSuffix(r.URL.Path, ".css")
		ttl = lang.Maybe(css, 1*time.Minute, 1*time.Hour)

	case runtime.Production:
		css := strings.HasSuffix(r.URL.Path, ".css")
		ttl = lang.Maybe(css, 3*time.Hour, 24*time.Hour)
	}

	webtools.SetCacheControl(w, ttl)
	c.H.ServeHTTP(w, r)
}
