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

// GetDomain extracts the domain name from a given url s.
//
// If s is not a valid url, the empty string is returned.
func GetDomain(s string) string {
	u, uerr := url.Parse(s)
	if uerr != nil {
		return ""
	}
	return u.Host
}

// Sanitize purges known tracker URL parameters.
//
// If s fails to parse as a url, the original string is returned.
func Sanitize(s string) string {
	u, err := url.Parse(s)
	if err != nil || u == nil {
		return s // leave as-is
	}

	query := u.Query()

	parameters := []string{
		// urchin tracking module
		"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
		"utm_social_handle_id", "utm_id", "utm_source_platform",
		"utm_creative_format", "utm_marketing_tactic",

		// socials
		"soc_src", "soc_trk",

		// ad clicks
		"gclid", "fbclid", "msclkid", "ttclid", "twclid", "dclid", "yclid",

		// mailers
		"mc_cid", "mc_eid", "_hsenc", "mkt_tok", "_kx", "_hsmi",

		// guce
		"guccounter", "guce_referrer", "guce_referrer_sig",
	}

	for _, parameter := range parameters {
		query.Del(parameter)
	}

	u.RawQuery = query.Encode()
	return u.String()
}
