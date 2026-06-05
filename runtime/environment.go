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

func (e Environment) Canonical(page string) template.URL {
	page = strings.TrimPrefix(page, "/")

	var canonical string

	switch e.environment {
	case Production:
		canonical = "https://" + e.domain + "/" + page
	case Staging:
		canonical = "https://stage." + e.domain + "/" + page
	default:
		canonical = "http://localhost:" + strconv.Itoa(LocalPort) + "/" + page
	}

	canonical = strings.TrimSuffix(canonical, "/")

	u, err := url.Parse(canonical)
	if err != nil {
		panic(fmt.Sprintf("runtime: unable to create url for page %q", page))
	}
	clean := u.String()

	return template.URL(clean)
}
