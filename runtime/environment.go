package runtime

import (
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"strconv"
	"strings"
)

// LocalPort is the normal port used for local development.
var LocalPort = 3000

// Platform is one of "local", "staging", or "production".
type Platform string

func Setup(c *Config) Environment {
	return Environment{
		domain:      c.Domain,
		environment: Platform(c.Environment),
	}
}

type Environment struct {
	domain      string
	environment Platform
}

const (
	Local      Platform = "local"
	Staging    Platform = "staging"
	Production Platform = "production"
)

func (e Environment) String() string {
	return string(e.Get())
}

func (e Environment) Get() Platform {
	return e.environment
}

func (e Environment) NonLocal() bool {
	return e.environment == Staging || e.environment == Production
}

func (e Environment) Validate() error {
	if e.domain == "" {
		return errors.New("domain must be set")
	}

	switch e.environment {
	case Local, Staging, Production:
		return nil
	default:
		return errors.New("environment must be set")
	}
}

func (e Environment) Canonical(urlpath string, args ...any) template.URL {
	s := fmt.Sprintf(urlpath, args...)
	p := strings.TrimPrefix(s, "/")

	var c string

	switch e.environment {
	case Production:
		c = "https://" + e.domain + "/" + p
	case Staging:
		c = "https://stage." + e.domain + "/" + p
	default:
		c = "http://localhost:" + strconv.Itoa(LocalPort) + "/" + p
	}

	canonical := strings.TrimSuffix(c, "/")

	u, err := url.Parse(canonical)
	if err != nil {
		panic(fmt.Sprintf("runtime: unable to create url for page %q", urlpath))
	}
	clean := u.String()

	return template.URL(clean)
}
