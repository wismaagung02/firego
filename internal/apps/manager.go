// Package apps manages the lifecycle of Firego "apps" — isolated backend
// instances each with their own Auth, Database, Storage, Hub and security Rules.
// The concept mirrors Firebase Projects.
package apps

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"strings"

	"firego/internal/auth"
	"firego/internal/database"
	"firego/internal/realtime"
	"firego/internal/rules"
	"firego/internal/storage"
)

var (
	ErrNotFound = errors.New("apps: app not found")
	ErrIDTaken  = errors.New("apps: app ID already in use")
	ErrProtected = errors.New("apps: cannot delete the default app")

	// validID allows lowercase letters, digits and hyphens, 3–30 chars,
	// must start with a letter or digit.
	validID = regexp.MustCompile(`^[a-z0-9][a-z0-9\-]{2,29}$`)
)

// Info is the persisted metadata for an app.
type Info struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	APIKey    string `json:"api_key"`
	CreatedAt int64  `json:"created_at"`
}

// App is a running app instance with its own isolated services.
type App struct {
	Info
	Auth  *auth.Service
	DB    *database.DB
	Store *storage.Store
	Hub   *realtime.Hub
	Rules *rules.RuleSet
}

// Manager creates, loads and deletes apps.
type Manager struct {
	mu           sync.RWMutex
	apps         map[string]*App
	dataDir      string
	masterSecret []byte
}

// New initialises a Manager from the given data directory. Any previously
// created apps are loaded from disk. A "default" app is created if none exist.
func New(dataDir string, masterSecret []byte) (*Manager, error) {
	m := &Manager{
		apps:         make(map[string]*App),
		dataDir:      dataDir,
		masterSecret: masterSecret,
	}
	if err := m.loadAll(); err != nil {
		return nil, err
	}
	if _, ok := m.apps["default"]; !ok {
		if _, err := m.create("default", "Default App"); err != nil {
			return nil, fmt.Errorf("apps: create default app: %w", err)
		}
	}
	return m, nil
}

func (m *Manager) registryPath() string {
	return filepath.Join(m.dataDir, "apps.json")
}

func (m *Manager) appDir(id string) string {
	return filepath.Join(m.dataDir, "apps", id)
}

// appSecret derives a deterministic per-app JWT signing secret so tokens
// issued by one app are never valid for another.
func (m *Manager) appSecret(id string) []byte {
	mac := hmac.New(sha256.New, m.masterSecret)
	mac.Write([]byte("firego-app:" + id))
	return mac.Sum(nil)
}

func (m *Manager) loadAll() error {
	data, err := os.ReadFile(m.registryPath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var infos []Info
	if err := json.Unmarshal(data, &infos); err != nil {
		return err
	}
	for _, info := range infos {
		app, err := m.initServices(info)
		if err != nil {
			return fmt.Errorf("apps: load %s: %w", info.ID, err)
		}
		m.apps[info.ID] = app
	}
	return nil
}

func (m *Manager) saveRegistry() error {
	infos := make([]Info, 0, len(m.apps))
	for _, a := range m.apps {
		infos = append(infos, a.Info)
	}
	data, err := json.MarshalIndent(infos, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.registryPath()), 0o755); err != nil {
		return err
	}
	tmp := m.registryPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, m.registryPath())
}

func (m *Manager) initServices(info Info) (*App, error) {
	dir := m.appDir(info.ID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	hub := realtime.NewHub()

	authSvc, err := auth.New(filepath.Join(dir, "users.json"), m.appSecret(info.ID))
	if err != nil {
		return nil, err
	}
	db, err := database.New(filepath.Join(dir, "database.json"), hub)
	if err != nil {
		return nil, err
	}
	store, err := storage.New(filepath.Join(dir, "storage"))
	if err != nil {
		return nil, err
	}
	rs, err := rules.New(filepath.Join(dir, "rules.json"))
	if err != nil {
		return nil, err
	}
	return &App{Info: info, Auth: authSvc, DB: db, Store: store, Hub: hub, Rules: rs}, nil
}

// create must be called with the write lock held.
func (m *Manager) create(id, name string) (*App, error) {
	info := Info{
		ID:        id,
		Name:      name,
		APIKey:    randomHex(20),
		CreatedAt: time.Now().Unix(),
	}
	app, err := m.initServices(info)
	if err != nil {
		return nil, err
	}
	m.apps[id] = app
	if err := m.saveRegistry(); err != nil {
		delete(m.apps, id)
		_ = os.RemoveAll(m.appDir(id))
		return nil, err
	}
	return app, nil
}

// Create validates the id and creates a new isolated app.
func (m *Manager) Create(id, name string) (*App, error) {
	if !validID.MatchString(id) {
		return nil, fmt.Errorf("apps: invalid id %q — use 3-30 lowercase letters, digits, hyphens", id)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = id
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.apps[id]; ok {
		return nil, ErrIDTaken
	}
	return m.create(id, name)
}

// Get returns the running App for the given id.
func (m *Manager) Get(id string) (*App, error) {
	m.mu.RLock()
	a, ok := m.apps[id]
	m.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}

// List returns the metadata of all registered apps.
func (m *Manager) List() []Info {
	m.mu.RLock()
	defer m.mu.RUnlock()
	infos := make([]Info, 0, len(m.apps))
	for _, a := range m.apps {
		infos = append(infos, a.Info)
	}
	return infos
}

// Delete removes an app and all its data. The "default" app is protected.
func (m *Manager) Delete(id string) error {
	if id == "default" {
		return ErrProtected
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.apps[id]; !ok {
		return ErrNotFound
	}
	delete(m.apps, id)
	_ = os.RemoveAll(m.appDir(id))
	return m.saveRegistry()
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
