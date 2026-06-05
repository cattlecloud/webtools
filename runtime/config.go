package runtime

import (
	"errors"
)

type Config struct {
	Domain      string `toml:"domain"`
	Environment string `toml:"environment"`
}

func (c *Config) Validate() error {
	switch {
	case c == nil:
		return errors.New("runtime config must be set")
	case c.Environment == "":
		return errors.New("runtime environment config must be set")
	case c.Domain == "":
		return errors.New("runtime domain config must be set")
	default:
		return nil
	}
}
