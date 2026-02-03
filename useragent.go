package webtools

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/mileusna/useragent"
)

// Origin contins request origination context from parsing request headers.
type Origin struct {
	Method    string
	Reference string
	UserAgent useragent.UserAgent
}

// From returns a parsed version of the Referer headers, including the domain
// and path without the protocol or query.
func (o *Origin) From() string {
	if o.Reference == "" {
		return "-"
	}

	u, _ := url.Parse(o.Reference)
	return u.Host + u.Path
}

// String returns the parsed user agent, including only the name and type of
// device being used (or bot).
func (o *Origin) String() string {
	var mode string
	switch {
	case o.UserAgent.Bot:
		mode = "bot"
	case o.UserAgent.Mobile:
		mode = "phone"
	case o.UserAgent.Tablet:
		mode = "tablet"
	case o.UserAgent.Desktop:
		mode = "desktop"
	default:
		mode = "unknown"
	}
	return o.UserAgent.Name + "/" + mode
}

// Origins parses the request headers to get information about the origins of
// the request, including ...
//
// - Referer
// - User-Agent
func Origins(r *http.Request) *Origin {
	method := strings.ToUpper(r.Method)
	reference := r.Header.Get("Referer")
	agent := r.Header.Get("User-Agent")
	ua := useragent.Parse(agent)
	return &Origin{
		Method:    method,
		Reference: reference,
		UserAgent: ua,
	}
}
