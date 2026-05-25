package htmx

import (
	"io"
	"strings"
)

// Text is plain text content for HTMX responses.
type Text[T ~string] struct {
	Content T
}

// Write writes the plain text content to w.
func (t *Text[T]) Write(w io.Writer) error {
	s := string(t.Content)
	_, err := io.Copy(w, strings.NewReader(s))
	return err
}
