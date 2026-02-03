package oauth

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

const size = 10

func TestVolatileCache_Get(t *testing.T) {
	t.Parallel()

	t.Run("cache hit", func(t *testing.T) {
		vc := NewVolatileCache[string](size)
		vc.Put("key-1", "hello", 1*time.Minute)

		val, ok := vc.Get("key-1")
		must.True(t, ok)
		must.Eq(t, "hello", val)
	})

	t.Run("cache miss", func(t *testing.T) {
		vc := NewVolatileCache[string](size)

		val, ok := vc.Get("non-existent")
		must.False(t, ok)
		must.Eq(t, "", val)
	})

	t.Run("expired item", func(t *testing.T) {
		// mock the clock to control time
		now := time.Now()
		vc := NewVolatileCache[string](size)
		vc.clock = func() time.Time { return now }

		// put item with 1 minute TTL
		vc.Put("key-1", "expired-meat", 1*time.Minute)

		// advance clock by 2 minutes
		now = now.Add(2 * time.Minute)

		val, ok := vc.Get("key-1")

		// should return false and the item should be purged
		must.False(t, ok)
		must.Eq(t, "", val)

		// verify it was actually deleted from the map
		vc.lock.Lock()
		_, exists := vc.data["key-1"]
		vc.lock.Unlock()
		must.False(t, exists)
	})
}

func TestVolatileCache_Put(t *testing.T) {
	t.Parallel()

	t.Run("overwrite existing key", func(t *testing.T) {
		vc := NewVolatileCache[int](size)

		vc.Put("count", 1, 1*time.Minute)
		vc.Put("count", 2, 1*time.Minute)

		val, ok := vc.Get("count")
		must.True(t, ok)
		must.Eq(t, 2, val)
	})
}
