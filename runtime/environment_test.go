package runtime

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestEnvironment_Validate(t *testing.T) {
	t.Parallel()

	t.Run("local", func(t *testing.T) {
		e := Setup(&Config{Environment: "local", Domain: "test.local"})
		err := e.Validate()
		must.NoError(t, err)
	})

	t.Run("staging", func(t *testing.T) {
		e := Setup(&Config{Environment: "staging", Domain: "example.com"})
		err := e.Validate()
		must.NoError(t, err)
	})

	t.Run("production", func(t *testing.T) {
		e := Setup(&Config{Environment: "production", Domain: "example.com"})
		err := e.Validate()
		must.NoError(t, err)
	})

	t.Run("missing environment", func(t *testing.T) {
		e := Setup(&Config{Environment: "", Domain: "example.com"})
		err := e.Validate()
		must.ErrorContains(t, err, "environment must be set")
	})

	t.Run("missing domain", func(t *testing.T) {
		e := Setup(&Config{Environment: "production", Domain: ""})
		err := e.Validate()
		must.ErrorContains(t, err, "domain must be set")
	})
}

func TestEnvironment_Canonical(t *testing.T) {
	t.Parallel()

	t.Run("production", func(t *testing.T) {
		e := Setup(&Config{Environment: "production", Domain: "example.com"})
		result := e.Canonical("/about")
		must.Eq(t, result, "https://example.com/about")
	})

	t.Run("staging", func(t *testing.T) {
		e := Setup(&Config{Environment: "staging", Domain: "example.com"})
		result := e.Canonical("/about")
		must.Eq(t, result, "https://stage.example.com/about")
	})

	t.Run("local", func(t *testing.T) {
		e := Setup(&Config{Environment: "local", Domain: "example.com"})
		result := e.Canonical("/about")
		must.Eq(t, result, "http://localhost:3000/about")
	})

	t.Run("missing slash", func(t *testing.T) {
		e := Setup(&Config{Environment: "local", Domain: "example.com"})
		result := e.Canonical("login")
		must.Eq(t, result, "http://localhost:3000/login")
	})

	t.Run("empty", func(t *testing.T) {
		e := Setup(&Config{Environment: "production", Domain: "example.com"})
		result := e.Canonical("")
		must.Eq(t, result, "https://example.com")
	})

	t.Run("format", func(t *testing.T) {
		e := Setup(&Config{Environment: "production", Domain: "example.com"})
		result := e.Canonical("/about/%s/%d", "content", 42)
		must.Eq(t, result, "https://example.com/about/content/42")
	})
}
