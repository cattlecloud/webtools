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

// Unique is a unique number assigned to each user that can be associated
// with any number of sessions. Typically a ROWID number from a database.
type Unique interface {
	~int | ~int64 | ~uint | ~uint64
}

type Sessions[U Unique] struct {
	Cache         Cache[*conceal.Text, U]
	CookieFactory *CookieFactory[U]
}

// NewSessions creates a new Sessions for managing sessions and cookies
// associated with those sessions.
func NewSessions[U Unique](cookies *CookieFactory[U], cache Cache[*conceal.Text, U]) *Sessions[U] {
	return &Sessions[U]{
		Cache:         cache,
		CookieFactory: cookies,
	}
}

func (s *Sessions[U]) Create(id U, ttl time.Duration) *http.Cookie {
	token := conceal.UUIDv4()
	cookie := s.CookieFactory.Create(id, token, ttl)
	s.Cache.Put(token, id, ttl)
	return cookie
}

func (s *Sessions[U]) Match(id U, token *conceal.Text) error {
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
