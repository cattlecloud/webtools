package webtools

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// MIMEType are correct identifier strings for various MIME types.
//
// Consider using one of the pre-defined types.
type MIMEType string

const (
	ContentTypeText MIMEType = "text/plain; charset=utf8"
	ContentTypeXML  MIMEType = "text/xml; charset=utf8"
	ContentTypeRSS  MIMEType = "application/rss+xml; charset=utf8"
)

// SetContentType sets the Content-Type header on w to the givien MIME
// compatible content type string.
func SetContentType(w http.ResponseWriter, filetype MIMEType) {
	w.Header().Add("Content-Type", string(filetype))
}

// RobotIndex are correct sentinel values for indicating whether a page
// should be indexed, as set in the X-Robots-Tag HTTP response header.
//
// Consider using one of the pre-defined types.
type RobotIndex string

const (
	RobotsNoIndex  RobotIndex = "noindex"
	RobotsYesIndex RobotIndex = "all"
)

// SetRobotsTag to a crawl control value (e.g. noindex)
func SetRobotsTag(w http.ResponseWriter, instruction RobotIndex) {
	w.Header().Add("X-Robots-Tag", string(instruction))
}

// SetCacheControl sets a private Cache-Control headers on w with the given
// duration, rounded to seconds.
func SetCacheControl(w http.ResponseWriter, ttl time.Duration) {
	f := ttl.Seconds()
	i := int(f)
	s := "private, max-age=" + strconv.Itoa(i)
	w.Header().Add("Cache-Control", s)
}

// SetBasicAuth sets the Authorization header on r, using the given username
// and password.
//
// NOTE: if either username or password is empty, no header is set.
func SetBasicAuth(r *http.Request, username, password string) {
	// do nothing if we are missing username or password
	if username == "" || password == "" {
		return
	}

	// crazy this is not in a standard library function
	credential := fmt.Sprintf("%s:%s", username, password)
	enc := base64.StdEncoding.EncodeToString([]byte(credential))
	r.Header.Set("Authorization", "Basic "+enc)
}
