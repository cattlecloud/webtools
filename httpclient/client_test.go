package httpclient

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

func TestGet(t *testing.T) {
	t.Parallel()

	c := Get()
	must.Eq(t, 1*time.Minute, c.Timeout)
}
