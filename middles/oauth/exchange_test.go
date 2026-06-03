package oauth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/shoenig/test/must"
)

func TestParseIDP(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/?idp=google", nil)
		result := ParseIDP(req)
		must.Eq(t, "google", result)
	})

	t.Run("missing idp panics", func(t *testing.T) {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
		must.Panic(t, func() {
			ParseIDP(req)
		})
	})
}

func TestParseCodeState(t *testing.T) {
	t.Parallel()

	t.Run("success with code and state", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodGet,
			"/?code=auth-code-123&state=state-token-456", nil,
		)
		code, state, err := ParseCodeState(req)
		must.NoError(t, err)
		must.Eq(t, "auth-code-123", code)
		must.Eq(t, "state-token-456", state)
	})

	t.Run("error returned from provider", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodGet,
			"/?error=access_denied&code=&state=", nil,
		)
		code, state, err := ParseCodeState(req)
		must.Error(t, err)
		must.Eq(t, "access_denied", err.Error())
		must.Eq(t, "", code)
		must.Eq(t, "", state)
	})

	t.Run("error from provider without code or state", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodGet,
			"/?error=access_denied", nil,
		)
		code, state, err := ParseCodeState(req)
		must.Error(t, err)
		must.Eq(t, "", code)
		must.Eq(t, "", state)
	})

	t.Run("missing code", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodGet,
			"/?state=state-token-456", nil,
		)
		code, state, err := ParseCodeState(req)
		must.Error(t, err)
		must.Eq(t, "", code)
		must.Eq(t, "", state)
	})

	t.Run("missing state", func(t *testing.T) {
		req := httptest.NewRequestWithContext(
			t.Context(), http.MethodGet,
			"/?code=auth-code-123", nil,
		)
		code, state, err := ParseCodeState(req)
		must.Error(t, err)
		must.Eq(t, "", code)
		must.Eq(t, "", state)
	})
}

func TestParseNonce(t *testing.T) {
	t.Parallel()

	t.Run("valid nonce in state", func(t *testing.T) {
		state := "nonce=12345678-1234-1234-1234-123456789abc"
		result := ParseNonce(state)
		must.Eq(t, "12345678-1234-1234-1234-123456789abc", result.Unveil())
	})

	t.Run("no nonce in state", func(t *testing.T) {
		state := "something without nonce"
		result := ParseNonce(state)
		must.Eq(t, "", result.Unveil())
	})

	t.Run("malformed nonce too short", func(t *testing.T) {
		state := "nonce=short"
		result := ParseNonce(state)
		must.Eq(t, "", result.Unveil())
	})

	t.Run("empty state", func(t *testing.T) {
		result := ParseNonce("")
		must.Eq(t, "", result.Unveil())
	})

	t.Run("nonce with extra params", func(t *testing.T) {
		state := "nonce=abcdef01-2345-6789-abcd-ef0123456789;extra=stuff"
		result := ParseNonce(state)
		must.Eq(t, "abcdef01-2345-6789-abcd-ef0123456789", result.Unveil())
	})

	t.Run("uppercase hex rejected", func(t *testing.T) {
		state := "nonce=ABCDEF01-2345-6789-ABCD-EF0123456789"
		result := ParseNonce(state)
		must.Eq(t, "", result.Unveil())
	})

	t.Run("nonce at end of longer state", func(t *testing.T) {
		state := "prefix_data;nonce=deadbeef-cafe-babe-0123-456789abcdef"
		result := ParseNonce(state)
		must.Eq(t, "deadbeef-cafe-babe-0123-456789abcdef", result.Unveil())
	})
}
