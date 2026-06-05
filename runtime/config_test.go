package runtime

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestConfig_Validate(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		c := (*Config)(nil)
		result := c.Validate()
		must.ErrorContains(t, result, "runtime config must be set")
	})

	t.Run("missing environment", func(t *testing.T) {
		c := &Config{
			Environment: "",
			Domain:      "example.com",
		}
		result := c.Validate()
		must.ErrorContains(t, result, "runtime environment config must be set")
	})

	t.Run("missing domain", func(t *testing.T) {
		c := &Config{
			Environment: "production",
			Domain:      "",
		}
		result := c.Validate()
		must.ErrorContains(t, result, "runtime domain config must be set")
	})
}
