// Package storage implements a simple object store (Firebase Cloud Storage
// style) backed by the local filesystem, with per-object content-type metadata.
package storage

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when an object does not exist.
var ErrNotFound = errors.New("storage: object not found")

// Object is the metadata describing a stored file.
type Object struct {
	Name        string `json:"name"`
	Size        int64  `json:"size"`
	ContentType string `json:"content_type"`
	UpdatedAt   int64  `json:"updated_at"`
}

// Store persists objects under a root directory.
type Store struct {
	mu   sync.RWMutex
	root string
	meta map[string]Object
}

// New opens (and creates if needed) a store rooted at dir.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "objects"), 0o755); err != nil {
		return nil, err
	}
	s := &Store{root: dir, meta: make(map[string]Object)}
	if err := s.loadMeta(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) metaPath() string { return filepath.Join(s.root, "metadata.json") }

func (s *Store) loadMeta() error {
	data, err := os.ReadFile(s.metaPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &s.meta)
}

// saveMeta must be called with the write lock held.
func (s *Store) saveMeta() error {
	data, err := json.MarshalIndent(s.meta, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.metaPath(), data, 0o600)
}

// sanitize normalizes an object name into a safe relative path.
func sanitize(name string) string {
	name = path.Clean("/" + strings.TrimSpace(name))
	return strings.TrimPrefix(name, "/")
}

func (s *Store) objectFile(name string) string {
	return filepath.Join(s.root, "objects", filepath.FromSlash(name))
}

// Put stores an object's bytes read from r.
func (s *Store) Put(name, contentType string, r io.Reader) (Object, error) {
	name = sanitize(name)
	if name == "" {
		return Object{}, errors.New("storage: empty object name")
	}
	dst := s.objectFile(name)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return Object{}, err
	}
	f, err := os.Create(dst)
	if err != nil {
		return Object{}, err
	}
	size, err := io.Copy(f, r)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return Object{}, err
	}

	if contentType == "" {
		contentType = "application/octet-stream"
	}
	obj := Object{Name: name, Size: size, ContentType: contentType, UpdatedAt: time.Now().Unix()}

	s.mu.Lock()
	s.meta[name] = obj
	err = s.saveMeta()
	s.mu.Unlock()
	return obj, err
}

// Open returns the metadata and a reader for the named object. The caller must
// close the reader.
func (s *Store) Open(name string) (Object, io.ReadCloser, error) {
	name = sanitize(name)
	s.mu.RLock()
	obj, ok := s.meta[name]
	s.mu.RUnlock()
	if !ok {
		return Object{}, nil, ErrNotFound
	}
	f, err := os.Open(s.objectFile(name))
	if err != nil {
		return Object{}, nil, err
	}
	return obj, f, nil
}

// Delete removes an object and its metadata.
func (s *Store) Delete(name string) error {
	name = sanitize(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.meta[name]; !ok {
		return ErrNotFound
	}
	delete(s.meta, name)
	if err := os.Remove(s.objectFile(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.saveMeta()
}

// List returns metadata for every object whose name starts with prefix.
func (s *Store) List(prefix string) []Object {
	prefix = sanitize(prefix)
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Object, 0, len(s.meta))
	for name, obj := range s.meta {
		if prefix == "" || strings.HasPrefix(name, prefix) {
			out = append(out, obj)
		}
	}
	return out
}
