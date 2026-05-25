package htmx

import (
	"net/http/httptest"
	"testing"

	"github.com/shoenig/test/must"
)

func Test_Redirect(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := SetRedirect(w, "/login")
	must.NoError(t, err)
	header := w.Header().Get("HX-Redirect")
	must.Eq(t, "/login", header)
}

func Test_SetNoSwap(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()
	err := SetNoSwap(w)
	must.NoError(t, err)

	header := w.Header().Get("HX-Reswap")
	must.Eq(t, "none", header)
}
