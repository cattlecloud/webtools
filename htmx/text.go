package htmx

import (
	"io"
	"strings"
)

// Text is plain text content for HTMX responses.
type Text struct {
	Content string
}

// Write writes the plain text content to w.
func (t *Text) Write(w io.Writer) error {
	_, err := io.Copy(w, strings.NewReader(t.Content))
	return err
}
