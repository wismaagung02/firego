// Package database implements a Firebase-style realtime JSON tree store.
// Data is held in memory as a nested map, persisted to disk, and every
// mutation is broadcast through a realtime hub.
package database

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"firego/internal/realtime"
)

// ErrNotFound is returned when reading a path that holds no value.
var ErrNotFound = errors.New("database: path not found")

// pushChars is the Firebase push-ID alphabet (modeled after their ordered,
// URL-safe keys so that generated keys sort chronologically).
const pushChars = "-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz"

// DB is the root of the JSON document tree.
type DB struct {
	mu   sync.RWMutex
	root map[string]any
	path string
	hub  *realtime.Hub
}

// New loads (or initializes) a database at path, publishing changes to hub.
func New(path string, hub *realtime.Hub) (*DB, error) {
	db := &DB{root: make(map[string]any), path: path, hub: hub}
	if err := db.load(); err != nil {
		return nil, err
	}
	return db, nil
}

func (db *DB) load() error {
	data, err := os.ReadFile(db.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &db.root)
}

// save must be called with the write lock held.
func (db *DB) save() error {
	data, err := json.MarshalIndent(db.root, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(db.path), 0o755); err != nil {
		return err
	}
	tmp := db.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, db.path)
}

// splitPath turns "/users/123/name" into ["users","123","name"].
func splitPath(p string) []string {
	p = strings.Trim(p, "/")
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// Get returns a deep copy of the value stored at path.
func (db *DB) Get(path string) (any, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	segs := splitPath(path)
	var cur any = db.root
	for _, seg := range segs {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, ErrNotFound
		}
		cur, ok = m[seg]
		if !ok {
			return nil, ErrNotFound
		}
	}
	return deepCopy(cur), nil
}

// Set replaces the value at path entirely (PUT semantics).
func (db *DB) Set(path string, value any) error {
	db.mu.Lock()
	segs := splitPath(path)
	if len(segs) == 0 {
		if m, ok := value.(map[string]any); ok {
			db.root = m
		} else {
			db.root = map[string]any{}
		}
	} else {
		parent := db.ensureParent(segs)
		parent[segs[len(segs)-1]] = value
	}
	err := db.save()
	db.mu.Unlock()
	if err != nil {
		return err
	}
	db.publish("put", path, value)
	return nil
}

// Update merges the fields of value into the object at path (PATCH semantics).
func (db *DB) Update(path string, value map[string]any) error {
	db.mu.Lock()
	segs := splitPath(path)
	target := db.root
	if len(segs) > 0 {
		parent := db.ensureParent(segs)
		last := segs[len(segs)-1]
		existing, ok := parent[last].(map[string]any)
		if !ok {
			existing = map[string]any{}
			parent[last] = existing
		}
		target = existing
	}
	for k, v := range value {
		target[k] = v
	}
	err := db.save()
	db.mu.Unlock()
	if err != nil {
		return err
	}
	db.publish("patch", path, value)
	return nil
}

// Push appends a child under path using a generated chronological key and
// returns that key (Firebase list semantics).
func (db *DB) Push(path string, value any) (string, error) {
	key := generatePushID()
	childPath := strings.TrimRight(path, "/") + "/" + key
	if err := db.Set(childPath, value); err != nil {
		return "", err
	}
	return key, nil
}

// Delete removes the value at path.
func (db *DB) Delete(path string) error {
	db.mu.Lock()
	segs := splitPath(path)
	if len(segs) == 0 {
		db.root = map[string]any{}
	} else {
		cur := db.root
		ok := true
		for _, seg := range segs[:len(segs)-1] {
			cur, ok = cur[seg].(map[string]any)
			if !ok {
				break
			}
		}
		if ok {
			delete(cur, segs[len(segs)-1])
		}
	}
	err := db.save()
	db.mu.Unlock()
	if err != nil {
		return err
	}
	db.publish("delete", path, nil)
	return nil
}

// ensureParent walks/creates the maps leading to the final segment and returns
// the parent map. Caller must hold the write lock.
func (db *DB) ensureParent(segs []string) map[string]any {
	cur := db.root
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	return cur
}

func (db *DB) publish(kind, path string, data any) {
	if db.hub == nil {
		return
	}
	db.hub.Publish(realtime.Event{Type: kind, Path: "/" + strings.Trim(path, "/"), Data: data})
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case map[string]any:
		c := make(map[string]any, len(t))
		for k, val := range t {
			c[k] = deepCopy(val)
		}
		return c
	case []any:
		c := make([]any, len(t))
		for i, val := range t {
			c[i] = deepCopy(val)
		}
		return c
	default:
		return v
	}
}

var (
	lastPushTime int64
	pushMu       sync.Mutex
	lastRand     [12]byte
)

// generatePushID produces a 20-char key that is globally unique and sorts by
// creation time, mirroring Firebase's push() key algorithm.
func generatePushID() string {
	pushMu.Lock()
	defer pushMu.Unlock()

	now := time.Now().UnixMilli()
	dup := now == lastPushTime
	lastPushTime = now

	var id [20]byte
	for i := 7; i >= 0; i-- {
		id[i] = pushChars[now%64]
		now /= 64
	}

	if !dup {
		b := make([]byte, 12)
		_, _ = rand.Read(b)
		for i := range lastRand {
			lastRand[i] = b[i] % 64
		}
	} else {
		// increment the previous random suffix
		for i := 11; i >= 0; i-- {
			if lastRand[i] != 63 {
				lastRand[i]++
				break
			}
			lastRand[i] = 0
		}
	}
	for i := 0; i < 12; i++ {
		id[8+i] = pushChars[lastRand[i]]
	}
	return string(id[:])
}
