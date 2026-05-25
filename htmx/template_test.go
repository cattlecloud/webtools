package htmx

import (
	"embed"
	"io/fs"
	"strings"
	"testing"

	"github.com/shoenig/test/must"
)

func TestFS(t *testing.T) {
	t.Parallel()

	sub := FS(testFiles, "testdata")
	must.NotNil(t, sub)

	entries, err := fs.ReadDir(sub, ".")
	must.NoError(t, err)
	must.Len(t, 4, entries)
}

var (
	//go:embed testdata/*
	testFiles embed.FS
)

func TestTemplate_Write(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		filename string
		fields   any
		funcs    map[string]any
		want     string
	}{
		{
			name:     "hello with name",
			filename: "hello.html",
			fields:   struct{ Name string }{Name: "World"},
			want:     `<p>Hello, World!</p>`,
		},
		{
			name:     "static content",
			filename: "static.html",
			fields:   nil,
			want:     `<p>This is static content</p>`,
		},
		{
			name:     "range items",
			filename: "items.html",
			fields:   struct{ Items []string }{Items: []string{"a", "b", "c"}},
			want:     `<ul><li>a</li><li>b</li><li>c</li></ul>`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sub, err := fs.Sub(testFiles, "testdata")
			must.NoError(t, err)
			tmpl := &Template{
				FS:       sub,
				Filename: tc.filename,
				Fields:   tc.fields,
			}
			if tc.funcs != nil {
				tmpl.Funcs = tc.funcs
			}
			var sb strings.Builder
			must.NoError(t, tmpl.Write(&sb))
			must.Eq(t, tc.want, sb.String())
		})
	}
}

func TestTemplate_Write_ParseError(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(testFiles, "testdata")
	must.NoError(t, err)

	tmpl := &Template{
		FS:       sub,
		Filename: "nonexistent.html",
		Fields:   nil,
	}
	var sb strings.Builder
	err = tmpl.Write(&sb)
	must.Error(t, err)
}

func TestTemplate_Write_ExecuteError(t *testing.T) {
	t.Parallel()

	sub, err := fs.Sub(testFiles, "testdata")
	must.NoError(t, err)

	tmpl := &Template{
		FS:       sub,
		Filename: "hello.html",
		Fields:   struct{ Missing string }{},
	}
	var sb strings.Builder
	err = tmpl.Write(&sb)
	must.Error(t, err)
	must.ErrorContains(t, err, "unable to execute")
}
