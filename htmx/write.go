package htmx

import (
	"fmt"
	"io"
	"net/http"

	"cattlecloud.net/go/webtools"
)

// An Interface is used to render an HTMX response. Included by default are
// implementations for rendering plain text, raw HTML, and file based Go
// html/templates.
type Interface interface {
	Write(io.Writer) error
}

// Write renders and writes an HTMX response using a variadic list of components,
// separated by newlines. It panics if any component fails to write.
func Write(w http.ResponseWriter, components ...Interface) error {
	webtools.SetContentType(w, webtools.ContentTypeHTML)

	for _, component := range components {
		if err := component.Write(w); err != nil {
			panic("[htmx] component failure: " + err.Error())
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return fmt.Errorf("htmx write failure: %w", err)
		}
	}

	// success!
	return nil
}
