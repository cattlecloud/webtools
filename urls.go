package webtools

import "net/url"

// CreateURL creates a *url.URL from the given origin, path, and request
// parameters that has been properly encoded and formatted.
//
// resource url must be valid; an invalid url will panic.
func CreateURL(origin, path string, params map[string]string) *url.URL {
	u, err := url.Parse(origin)
	if err != nil {
		// incoming resource URL should be known at compile time.
		panic("web: cannot parse url " + origin)
	}

	// Set the URL path
	u.Path = path

	// set the query parameters
	query := make(url.Values, len(params))
	for k, v := range params {
		query.Add(k, v)
	}
	u.RawQuery = query.Encode()
	return u
}
