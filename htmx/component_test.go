package htmx

import (
	"strings"
	"testing"

	"github.com/shoenig/test/must"
)

func TestComponent_Write(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		html   string
		fields any
		funcs  map[string]any
		want   string
	}{
		{
			name:   "simple string",
			html:   `<p>hello</p>`,
			fields: nil,
			want:   `<p>hello</p>`,
		},
		{
			name:   "with fields",
			html:   `<p>{{.Message}}</p>`,
			fields: struct{ Message string }{Message: "world"},
			want:   `<p>world</p>`,
		},
		{
			name:   "empty fields",
			html:   `<p>static</p>`,
			fields: struct{}{},
			want:   `<p>static</p>`,
		},
		{
			name:   "custom func",
			html:   `<p>{{hello}}</p>`,
			fields: nil,
			funcs:  map[string]any{"hello": func() string { return "custom func" }},
			want:   `<p>custom func</p>`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c := &Component{
				HTML:   tc.html,
				Fields: tc.fields,
			}
			if tc.funcs != nil {
				c.Funcs = tc.funcs
			}
			var sb strings.Builder
			must.NoError(t, c.Write(&sb))
			must.Eq(t, tc.want, sb.String())
		})
	}
}

func TestComponent_Write_ParseError(t *testing.T) {
	t.Parallel()

	c := &Component{
		HTML: `<p>{{.Invalid}</p>`,
	}
	var sb strings.Builder
	err := c.Write(&sb)
	must.Error(t, err)
	must.ErrorContains(t, err, "unable to parse template")
}

func TestComponent_Write_ExecuteError(t *testing.T) {
	t.Parallel()

	c := &Component{
		HTML:   `<p>{{.Missing}}</p>`,
		Fields: struct{ Other string }{Other: "value"},
	}
	var sb strings.Builder
	err := c.Write(&sb)
	must.Error(t, err)
	must.ErrorContains(t, err, "unable to execute template")
}
