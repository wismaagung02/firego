package database

import (
	"path/filepath"
	"testing"

	"firego/internal/realtime"
)

func newTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := New(filepath.Join(t.TempDir(), "db.json"), realtime.NewHub())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return db
}

func TestSetGetNested(t *testing.T) {
	db := newTestDB(t)
	if err := db.Set("users/alice/name", "Alice"); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := db.Get("users/alice/name")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "Alice" {
		t.Fatalf("got %v, want Alice", got)
	}
}

func TestUpdateMerges(t *testing.T) {
	db := newTestDB(t)
	_ = db.Set("config", map[string]any{"a": 1.0, "b": 2.0})
	if err := db.Update("config", map[string]any{"b": 3.0, "c": 4.0}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ := db.Get("config")
	m := got.(map[string]any)
	if m["a"] != 1.0 || m["b"] != 3.0 || m["c"] != 4.0 {
		t.Fatalf("merge wrong: %v", m)
	}
}

func TestPushGeneratesOrderedKeys(t *testing.T) {
	db := newTestDB(t)
	k1, err := db.Push("list", "first")
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	k2, _ := db.Push("list", "second")
	if k1 == k2 {
		t.Fatal("push keys should be unique")
	}
	if k1 >= k2 {
		t.Fatalf("push keys should sort chronologically: %s vs %s", k1, k2)
	}
}

func TestDelete(t *testing.T) {
	db := newTestDB(t)
	_ = db.Set("x/y", "z")
	if err := db.Delete("x/y"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := db.Get("x/y"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestPersistenceReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db.json")
	db, _ := New(path, nil)
	_ = db.Set("greeting", "halo")

	reopened, err := New(path, nil)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	got, _ := reopened.Get("greeting")
	if got != "halo" {
		t.Fatalf("persistence failed, got %v", got)
	}
}
