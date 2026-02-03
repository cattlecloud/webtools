package nonces

import (
	"testing"

	"github.com/shoenig/test/must"
)

func TestMint_normal(t *testing.T) {
	t.Parallel()

	m := New()

	token := m.Create()
	must.UUIDv4(t, token.Unveil())

	err := m.Consume(token)
	must.NoError(t, err)

	err2 := m.Consume(token)
	must.ErrorIs(t, err2, ErrTokenNotValid)
}
