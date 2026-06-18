package apps

import (
	"encoding/json"
	"errors"
	"os"
	"sync"
)

// RemoteConfig is a per-app key-value configuration store, similar to Firebase Remote Config.
// Values can be any JSON-compatible type (string, number, bool, object, array).
type RemoteConfig struct {
	mu     sync.RWMutex
	params map[string]any
	path   string
}

func newRemoteConfig(path string) (*RemoteConfig, error) {
	rc := &RemoteConfig{path: path, params: map[string]any{}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return rc, nil
	}
	if err != nil {
		return nil, err
	}
	return rc, json.Unmarshal(data, &rc.params)
}

// Get returns a copy of all parameters.
func (rc *RemoteConfig) Get() map[string]any {
	rc.mu.RLock()
	defer rc.mu.RUnlock()
	out := make(map[string]any, len(rc.params))
	for k, v := range rc.params {
		out[k] = v
	}
	return out
}

// Set replaces all parameters and persists to disk.
func (rc *RemoteConfig) Set(params map[string]any) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	data, err := json.MarshalIndent(params, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(rc.path, data, 0o600); err != nil {
		return err
	}
	rc.params = params
	return nil
}

// Merge updates individual keys without replacing the entire config.
func (rc *RemoteConfig) Merge(updates map[string]any) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for k, v := range updates {
		rc.params[k] = v
	}
	data, err := json.MarshalIndent(rc.params, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rc.path, data, 0o600)
}

// DeleteKey removes a single parameter and persists.
func (rc *RemoteConfig) DeleteKey(key string) error {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	delete(rc.params, key)
	data, err := json.MarshalIndent(rc.params, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(rc.path, data, 0o600)
}
