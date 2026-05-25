package htmx

import "net/http"

// SetRedirect forces a client-side redirect using HTMX.
//
// Must use this instead of http.SetRedirect when doing a redirect from a request
// triggered by an HTMX element.
func SetRedirect(w http.ResponseWriter, path string) error {
	w.Header().Add("HX-Redirect", path)
	w.WriteHeader(http.StatusFound)
	return nil
}

// SetNoSwap disables the hx-swap attribute; causing the existing content to
// remain in place after HTMX transition.
//
// Useful for setting error messages on forms, allowing users to try again.
func SetNoSwap(w http.ResponseWriter) error {
	w.Header().Set("HX-Reswap", "none")
	return nil
}
