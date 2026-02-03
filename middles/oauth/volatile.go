package oauth

import (
	"sync"
	"time"
)

type item[T any] struct {
	value      T
	expiration time.Time
}

// NewVolatileCache creates an in-memory implementation of Cache.
func NewVolatileCache[T any](size int) *VolatileCache[T] {
	return &VolatileCache[T]{
		lock:  new(sync.Mutex),
		data:  make(map[string]*item[T], size),
		clock: time.Now,
	}
}

// VolatileCache is an in-memory implementation of Cache.
//
// This implementation should likely not be used for production services; doing
// so implies that any process restart will cause all sessions to be wiped out.
// Most services should make use of memcached, redis, etc.
//
// Additionally this implementation does not purge old sessions; expired
// sessions linger forever if never accessed again. A better in-memory cache
// would make use of an LRU.
type VolatileCache[T any] struct {
	lock  *sync.Mutex
	data  map[string]*item[T]
	clock func() time.Time
}

func (vc *VolatileCache[T]) Get(path string) (T, bool) {
	now := vc.clock()

	vc.lock.Lock()
	defer vc.lock.Unlock()

	item, exists := vc.data[path]

	// check item was in the cache
	if !exists {
		var empty T
		return empty, false
	}

	// check item expiration and purge if necessary
	if now.After(item.expiration) {
		delete(vc.data, path)
		var empty T
		return empty, false
	}

	return item.value, exists
}

func (vc *VolatileCache[T]) Put(path string, value T, ttl time.Duration) {
	now := vc.clock()

	vc.lock.Lock()
	defer vc.lock.Unlock()

	// store the value
	vc.data[path] = &item[T]{
		expiration: now.Add(ttl),
		value:      value,
	}
}
