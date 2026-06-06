package expcache

import (
	"testing"
	"time"

	"github.com/shoenig/test/must"
)

var (
	ten = func() time.Duration { return 10 * time.Millisecond }
)

func TestCache(t *testing.T) {
	t.Parallel()

	c := New[int](ten)

	c.Insert("one", 1)
	c.Insert("two", 2)

	v1, b1 := c.Get("one")
	must.Eq(t, 1, v1)
	must.True(t, b1)

	v2, b2 := c.Get("two")
	must.Eq(t, 2, v2)
	must.True(t, b2)

	// expire both items in the cache
	time.Sleep(11 * time.Millisecond)

	v3, b3 := c.Get("one")
	must.Eq(t, 1, v3)
	must.False(t, b3)

	v4, b4 := c.Get("two")
	must.Eq(t, 2, v4)
	must.False(t, b4)

	// insert a non-expired item
	c.Insert("three", 3)

	// new element should not be expired
	v5, b5 := c.Get("three")
	must.Eq(t, 3, v5)
	must.True(t, b5)

	// old element should still be expired
	v6, b6 := c.Get("one")
	must.Eq(t, 1, v6)
	must.False(t, b6)

	// non-existent element should be expired
	_, b7 := c.Get("oops")
	must.False(t, b7)
}

func TestCache_Touch(t *testing.T) {
	t.Parallel()

	c := New[int](ten)

	c.Insert("one", 1)
	c.Insert("two", 2)

	// expire the cache
	time.Sleep(11 * time.Millisecond)

	// bump the cache for the "two" key
	c.Touch("two")

	v1, b1 := c.Get("one")
	must.Eq(t, 1, v1)
	must.False(t, b1) // expired

	v2, b2 := c.Get("two")
	must.Eq(t, 2, v2)
	must.True(t, b2) // not expired
}

func TestCache_DynamicTTL(t *testing.T) {
	t.Parallel()

	c := New[int](ten)

	c.Insert("one", 1)
	c.Insert("two", 2)

	v1, b1 := c.Get("one")
	must.Eq(t, 1, v1)
	must.True(t, b1)

	v2, b2 := c.Get("two")
	must.Eq(t, 2, v2)
	must.True(t, b2)

	// expire the cache
	time.Sleep(11 * time.Millisecond)

	// must no longer be in cache
	v3, b3 := c.Get("one")
	must.Eq(t, 1, v3)
	must.False(t, b3)

	v4, b4 := c.Get("two")
	must.Eq(t, 2, v4)
	must.False(t, b4)
}

func TestCache_GetMap(t *testing.T) {
	t.Parallel()

	c := New[int](ten)

	c.Insert("one", 1)
	c.Insert("two", 2)
	c.Insert("three", 3)
	c.Insert("four", 4)
	c.Insert("five", 5)

	results := c.GetMap("one", "three", "five")
	must.MapLen(t, 3, results)
	must.Eq(t, Maybe[int]{Item: 1, Usable: true}, results["one"])
	must.Eq(t, Maybe[int]{Item: 3, Usable: true}, results["three"])
	must.Eq(t, Maybe[int]{Item: 5, Usable: true}, results["five"])

	// expire the cache
	time.Sleep(11 * time.Millisecond)

	results2 := c.GetMap("two", "four")
	must.MapLen(t, 2, results2)
	must.Eq(t, Maybe[int]{Usable: false}, results["two"])
	must.Eq(t, Maybe[int]{Usable: false}, results["four"])
}
