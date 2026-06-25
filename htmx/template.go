package htmx

import (
	"embed"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path/filepath"
	"strings"
)

// FS wraps an embedded filesystem with a subdirectory for template loading.
func FS(filesystem embed.FS, directory string) fs.FS {
	sub, err := fs.Sub(filesystem, directory)
	if err != nil {
		panic(fmt.Sprintf("unable to open sub-filesystem at %s: %v", directory, err))
	}
	return sub
}

// Template represents an html/template file loaded from an embedded filesystem.
// Fields provides data to the template via the dot (.) context.
// Funcs allows providing custom template functions.
type Template struct {
	FS       fs.FS
	Filename string
	Fields   any
	Funcs    template.FuncMap
}

// Write renders the template file with Fields and writes the result to w.
func (t *Template) Write(w io.Writer) error {
	root := template.New("htmx-root").Funcs(t.Funcs)
	tree, terr := root.ParseFS(t.FS, filepath.Base(t.Filename))
	if terr != nil {
		return fmt.Errorf("unable to parse filesystem: %w", terr)
	}

	x := tree.Lookup(strings.TrimSuffix(filepath.Base(t.Filename), ".html"))
	if x == nil {
		return fmt.Errorf("unable to lookup %q", t.Filename)
	}

	xerr := x.Execute(w, t.Fields)
	if xerr != nil {
		return fmt.Errorf("unable to execute %q: %w", t.Filename, xerr)
	}

	return nil
}
