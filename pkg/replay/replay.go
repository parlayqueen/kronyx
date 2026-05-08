package replay

import (
	"sync"
	"time"
)

type Registry struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func NewRegistry() *Registry { return &Registry{used: map[string]time.Time{}} }

func (r *Registry) MarkUsed(tokenID string, ttl time.Duration) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.used[tokenID]; ok && time.Now().Before(exp) {
		return false
	}
	r.used[tokenID] = time.Now().Add(ttl)
	return true
}

func (r *Registry) GC() {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	for k, exp := range r.used {
		if now.After(exp) {
			delete(r.used, k)
		}
	}
}
