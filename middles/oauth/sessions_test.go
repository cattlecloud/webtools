package oauth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/shoenig/go-conceal"
	"github.com/shoenig/test/must"
)

// mockCache provides an in-memory implementation of the Cache interface
type mockCache struct {
	storage map[string]rowid
}

func (m *mockCache) Get(k *conceal.Text) (rowid, bool) {
	id, ok := m.storage[k.Unveil()]
	return id, ok
}

func (m *mockCache) Put(k *conceal.Text, v rowid, _ time.Duration) {
	m.storage[k.Unveil()] = v
}

func TestSessions_Create(t *testing.T) {
	t.Parallel()

	cache := &mockCache{storage: make(map[string]rowid)}

	// initialize the sessions manager with the cache and a cookie factory
	sessions := NewSessions(&CookieFactory[rowid]{
		Name:   "session-token",
		Secure: true,
		Clock:  testNow,
	}, cache)

	id := rowid(12345)
	ttl := 1 * time.Hour

	cookie := sessions.Create(id, ttl)

	// ensure the cookie is as expected
	must.NotNil(t, cookie)
	must.Eq(t, "session-token", cookie.Name)

	// decode the cookie value content
	b, berr := base64.StdEncoding.DecodeString(cookie.Value)
	must.NoError(t, berr)

	// unamrshal the json value content
	cc := new(CookieContent[rowid])
	jerr := json.Unmarshal(b, cc)
	must.NoError(t, jerr)

	// lookup the cookie's token in the caceh
	storedID, exists := cache.Get(cc.Token())
	must.True(t, exists)
	must.Eq(t, id, storedID)
}

func TestSessions_Match(t *testing.T) {
	t.Parallel()

	cookies := (*CookieFactory[rowid])(nil)
	cache := &mockCache{storage: make(map[string]rowid)}
	sessions := NewSessions(cookies, cache)

	id := rowid(12345)
	token := conceal.UUIDv4()

	// seed the cache with a known session
	cache.Put(token, id, 1*time.Hour)

	t.Run("match successful", func(t *testing.T) {
		err := sessions.Match(id, token)
		must.NoError(t, err)
	})

	t.Run("match not found", func(t *testing.T) {
		unknownToken := conceal.UUIDv4()
		err := sessions.Match(id, unknownToken)
		must.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("match not a match", func(t *testing.T) {
		wrongID := rowid(99999)
		err := sessions.Match(wrongID, token)
		must.ErrorIs(t, err, ErrNotMatch)
	})
}
