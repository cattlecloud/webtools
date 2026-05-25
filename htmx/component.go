package htmx

import (
	"fmt"
	"html/template"
	"io"
)

// Component is a raw HTML string rendered using html/template.
// Fields provides data to the template via the dot (.) context.
// Funcs allows providing custom template functions.
type Component struct {
	HTML   string
	Fields any
	Funcs  template.FuncMap
}

// Write renders the HTML template with Fields and writes the result to w.
func (c *Component) Write(w io.Writer) error {
	t, terr := template.New("htmx-root").Funcs(c.Funcs).Parse(c.HTML)
	if terr != nil {
		return fmt.Errorf("unable to parse template: %w", terr)
	}

	xerr := t.Execute(w, c.Fields)
	if xerr != nil {
		return fmt.Errorf("unable to execute template: %w", xerr)
	}

	return nil
}
