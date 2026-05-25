package htmx

import (
	"strings"
	"testing"

	"github.com/shoenig/test/must"
)

func TestText_Write(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "simple string",
			content: "hello world",
			want:    "hello world",
		},
		{
			name:    "empty string",
			content: "",
			want:    "",
		},
		{
			name:    "html content",
			content: "<p>hello</p>",
			want:    "<p>hello</p>",
		},
		{
			name:    "multiline content",
			content: "line1\nline2\nline3",
			want:    "line1\nline2\nline3",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			text := &Text{Content: tc.content}
			var sb strings.Builder
			must.NoError(t, text.Write(&sb))
			must.Eq(t, tc.want, sb.String())
		})
	}
}
