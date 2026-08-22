package triage

import "sync"

type Cache struct {
	mu    sync.RWMutex
	items map[string]string
}

func NewCache() *Cache {
	return &Cache{items: make(map[string]string)}
}

func (c *Cache) Get(id string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	value, ok := c.items[id]
	return value, ok
}

func (c *Cache) Set(id, summary string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.items[id] = summary
}
