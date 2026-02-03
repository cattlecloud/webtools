package oauth

import (
	"errors"
	"net/http"
	"time"

	"github.com/shoenig/go-conceal"
)

var (
	// ErrNotFound indidcates no oauth session was found in the request context.
	ErrNotFound = errors.New("session: not found")

	// ErrNotMatch indicates the stored session does not match the session from
	// the request context, likely indicating a malicious user fudging a session
	// value.
	ErrNotMatch = errors.New("session: not a match")
)

// Cache could be implemented using an in-memory cache, a memcached instance,
// or even persistent storage.
type Cache[K, T any] interface {
	Get(K) (T, bool)
	Put(K, T, time.Duration)
}

type Identity int64

type Sessions struct {
	Cache         Cache[*conceal.Text, Identity]
	CookieFactory *CookieFactory
}

func NewSessions(cache Cache[*conceal.Text, Identity]) *Sessions {
	return &Sessions{
		Cache: cache,
	}
}

func (s *Sessions) Create(id Identity, ttl time.Duration) *http.Cookie {
	token := conceal.UUIDv4()
	cookie := s.CookieFactory.Create(id, token, ttl)
	s.Cache.Put(token, id, ttl)
	return cookie
}

func (s *Sessions) Match(id Identity, token *conceal.Text) error {
	actual, exists := s.Cache.Get(token)

	switch {
	case !exists:
		return ErrNotFound
	case id != actual:
		return ErrNotMatch
	default:
		return nil
	}
}
