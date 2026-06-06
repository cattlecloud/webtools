package expcache

import (
	"sync"
	"time"

	"github.com/shoenig/lang"
)

// TimeToLiveFunc represents the function used by a Cache to determine how long
// an item should be accessible in the cache.
//
// Often returns a static value, or a value based on time of day, etc.
type TimeToLiveFunc func() time.Duration

// TTL returns a TimeToLiveFunc around a static ttl duration.
func TTL(duration time.Duration) TimeToLiveFunc {
	return func() time.Duration {
		return duration
	}
}

// Cache is an expiry cache that does not prune out of date elements.
//
// Is thread-safe.
type Cache[T any] struct {
	ttl func() time.Duration

	lock  *sync.Mutex
	items map[string]*lang.Pair[T, time.Time]
}

// Dynamic creates an expiry cache using a functional ttl computed based on the
// current time.
func New[T any](f TimeToLiveFunc) *Cache[T] {
	return &Cache[T]{
		lock:  new(sync.Mutex),
		items: make(map[string]*lang.Pair[T, time.Time]),
		ttl:   f,
	}
}

func (c *Cache[T]) expiration(now time.Time) time.Time {
	ttl := c.ttl()
	exp := now.Add(ttl)
	return exp
}

// Insert item into the cache at the given key.
func (c *Cache[T]) Insert(key string, item T) {
	now := time.Now()
	exp := c.expiration(now)
	pair := &lang.Pair[T, time.Time]{A: item, B: exp}

	lang.Critical(c.lock, func() {
		c.items[key] = pair
	})
}

// Insert each item of items into the cache at the associated key.
func (c *Cache[T]) InsertMap(items map[string]T) {
	now := time.Now()
	exp := c.expiration(now)

	lang.Critical(c.lock, func() {
		for key, item := range items {
			pair := &lang.Pair[T, time.Time]{A: item, B: exp}
			c.items[key] = pair
		}
	})
}

// Touch bumps the insertion time associated with key to be the current time,
// thus extending the effective TTL of the associated value.
func (c *Cache[T]) Touch(key string) {
	now := time.Now()
	exp := c.expiration(now)

	lang.Critical(c.lock, func() {
		if v, ok := c.items[key]; ok {
			v.B = exp
		}
	})
}

// Get returns the value and whether the cache considers the value to be usable.
// The value is not usable if it does not exist, or is past its TTL expiration.
func (c *Cache[T]) Get(key string) (T, bool) {
	c.lock.Lock()
	value, exists := c.items[key]
	c.lock.Unlock()

	if !exists {
		var empty T
		return empty, false
	}

	now := time.Now()
	expired := now.After(value.B)

	return value.A, !expired
}

type Maybe[T any] struct {
	Item   T
	Usable bool
}

// GetMap returns a Maybe for each given key. The Maybe indicates whether the item is
// considered usable. An item is not usable if no value exists for a given key, or the
// value for the given key is past its TTL expiration.
func (c *Cache[T]) GetMap(keys ...string) map[string]Maybe[T] {
	m := make(map[string]Maybe[T], len(keys))

	lang.Critical(c.lock, func() {
		for _, key := range keys {
			if value, exists := c.items[key]; exists {
				now := time.Now()
				expired := now.After(value.B)
				m[key] = Maybe[T]{Item: value.A, Usable: !expired}
			} else {
				m[key] = Maybe[T]{Usable: false}
			}
		}
	})

	return m
}
