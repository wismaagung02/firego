// Package auth implements user registration, login and JWT issuing for Firego.
// User records are persisted as JSON on disk and protected with salted,
// iterated SHA-256 password hashing (no external dependencies).
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"firego/internal/jwt"
)

const (
	hashIterations = 100_000
	tokenTTL       = 24 * time.Hour
)

var (
	// ErrEmailTaken is returned when registering an already-used email.
	ErrEmailTaken = errors.New("auth: email already registered")
	// ErrInvalidCredentials is returned on a failed login.
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	// ErrUserNotFound is returned when a uid cannot be resolved.
	ErrUserNotFound = errors.New("auth: user not found")
	// ErrWeakInput is returned for empty/short credentials.
	ErrWeakInput = errors.New("auth: email required and password must be at least 6 characters")
)

// User is the public representation of an account (never includes the hash).
type User struct {
	UID       string `json:"uid"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

type storedUser struct {
	User
	Salt string `json:"salt"`
	Hash string `json:"hash"`
}

// Service manages accounts and token issuing.
type Service struct {
	mu     sync.RWMutex
	users  map[string]*storedUser // keyed by lowercase email
	byUID  map[string]*storedUser
	path   string
	secret []byte
}

// New creates an auth service backed by the file at path, signing tokens with
// secret. Existing users are loaded if the file is present.
func New(path string, secret []byte) (*Service, error) {
	s := &Service{
		users:  make(map[string]*storedUser),
		byUID:  make(map[string]*storedUser),
		path:   path,
		secret: secret,
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) load() error {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var users []*storedUser
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	for _, u := range users {
		s.users[strings.ToLower(u.Email)] = u
		s.byUID[u.UID] = u
	}
	return nil
}

// save must be called with the lock held.
func (s *Service) save() error {
	users := make([]*storedUser, 0, len(s.users))
	for _, u := range s.users {
		users = append(users, u)
	}
	data, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func hashPassword(password, salt string) string {
	h := []byte(salt + password)
	for i := 0; i < hashIterations; i++ {
		sum := sha256.Sum256(h)
		h = sum[:]
	}
	return hex.EncodeToString(h)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Register creates a new account and returns the user plus a fresh token.
func (s *Service) Register(email, password string) (*User, string, error) {
	email = strings.TrimSpace(email)
	if email == "" || len(password) < 6 {
		return nil, "", ErrWeakInput
	}
	key := strings.ToLower(email)

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[key]; ok {
		return nil, "", ErrEmailTaken
	}

	salt := randomHex(16)
	u := &storedUser{
		User: User{
			UID:       randomHex(12),
			Email:     email,
			CreatedAt: time.Now().Unix(),
		},
		Salt: salt,
		Hash: hashPassword(password, salt),
	}
	s.users[key] = u
	s.byUID[u.UID] = u
	if err := s.save(); err != nil {
		delete(s.users, key)
		delete(s.byUID, u.UID)
		return nil, "", fmt.Errorf("auth: persist user: %w", err)
	}

	token, err := s.issueToken(u)
	if err != nil {
		return nil, "", err
	}
	user := u.User
	return &user, token, nil
}

// Login verifies credentials and returns the user plus a fresh token.
func (s *Service) Login(email, password string) (*User, string, error) {
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(strings.TrimSpace(email))]
	s.mu.RUnlock()
	if !ok {
		return nil, "", ErrInvalidCredentials
	}

	got := hashPassword(password, u.Salt)
	if subtle.ConstantTimeCompare([]byte(got), []byte(u.Hash)) != 1 {
		return nil, "", ErrInvalidCredentials
	}

	token, err := s.issueToken(u)
	if err != nil {
		return nil, "", err
	}
	user := u.User
	return &user, token, nil
}

func (s *Service) issueToken(u *storedUser) (string, error) {
	return jwt.Sign(jwt.Claims{Subject: u.UID, Email: u.Email}, s.secret, tokenTTL)
}

// Verify validates a bearer token and returns the associated user.
func (s *Service) Verify(token string) (*User, error) {
	claims, err := jwt.Parse(token, s.secret)
	if err != nil {
		return nil, err
	}
	s.mu.RLock()
	u, ok := s.byUID[claims.Subject]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrUserNotFound
	}
	user := u.User
	return &user, nil
}
