// Package realtime provides a lightweight publish/subscribe hub used to stream
// database changes to clients over Server-Sent Events (SSE).
package realtime

import (
	"sync"
)

// Event describes a change at a database path.
type Event struct {
	Type string `json:"type"` // "put", "patch" or "delete"
	Path string `json:"path"`
	Data any    `json:"data"`
}

type subscriber struct {
	prefix string
	ch     chan Event
}

// Hub fans out events to subscribers interested in a path subtree.
type Hub struct {
	mu   sync.RWMutex
	subs map[*subscriber]struct{}
}

// NewHub creates an empty hub.
func NewHub() *Hub {
	return &Hub{subs: make(map[*subscriber]struct{})}
}

// Subscribe registers interest in events at or below prefix. The returned
// channel receives events until unsubscribe is called.
func (h *Hub) Subscribe(prefix string) (<-chan Event, func()) {
	sub := &subscriber{prefix: prefix, ch: make(chan Event, 16)}
	h.mu.Lock()
	h.subs[sub] = struct{}{}
	h.mu.Unlock()

	unsubscribe := func() {
		h.mu.Lock()
		if _, ok := h.subs[sub]; ok {
			delete(h.subs, sub)
			close(sub.ch)
		}
		h.mu.Unlock()
	}
	return sub.ch, unsubscribe
}

// matches reports whether an event at evPath is relevant to a subscriber
// watching prefix (i.e. the event is at, above, or below the watched node).
func matches(prefix, evPath string) bool {
	if prefix == "" || prefix == evPath {
		return true
	}
	// event inside the watched subtree
	if len(evPath) > len(prefix) && evPath[:len(prefix)] == prefix && evPath[len(prefix)] == '/' {
		return true
	}
	// watched node is inside the changed subtree
	if len(prefix) > len(evPath) && prefix[:len(evPath)] == evPath && prefix[len(evPath)] == '/' {
		return true
	}
	return false
}

// Publish delivers an event to every matching subscriber. Slow subscribers
// whose buffer is full are skipped rather than blocking the publisher.
func (h *Hub) Publish(ev Event) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for sub := range h.subs {
		if !matches(sub.prefix, ev.Path) {
			continue
		}
		select {
		case sub.ch <- ev:
		default:
		}
	}
}
