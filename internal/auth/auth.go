// Package auth implements user registration, login, logout and JWT issuing
// for Firego. Passwords are hashed with bcrypt (cost 12). Each token carries
// a unique jti claim that is added to an in-memory blacklist on logout,
// making session termination immediate without extra server-side storage.
package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"firego/internal/jwt"

	"golang.org/x/crypto/bcrypt"
)

// DefaultBcryptCost is the work factor for bcrypt. Cost 12 ≈ 250 ms on a
// modern server — deliberately slow to resist offline cracking.
const DefaultBcryptCost = 12

const tokenTTL = 24 * time.Hour

var (
	ErrEmailTaken         = errors.New("auth: email already registered")
	ErrInvalidCredentials = errors.New("auth: invalid email or password")
	ErrUserNotFound       = errors.New("auth: user not found")
	ErrWeakInput          = errors.New("auth: valid email required and password must be at least 6 characters")
	ErrTokenRevoked       = errors.New("auth: token has been revoked")

	emailRE = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// User is the public representation of an account (password hash never exposed).
type User struct {
	UID       string `json:"uid"`
	Email     string `json:"email"`
	CreatedAt int64  `json:"created_at"`
}

type storedUser struct {
	User
	BCryptHash string `json:"hash"` // bcrypt output already embeds the salt
}

type blacklistEntry struct {
	expiresAt int64
}

// Service manages accounts, token issuing, and a revocation blacklist.
type Service struct {
	mu       sync.RWMutex
	users    map[string]*storedUser // keyed by lowercase email
	byUID    map[string]*storedUser
	path     string
	secret   []byte
	hashCost int

	blackMu   sync.RWMutex
	blacklist map[string]blacklistEntry // jti → expiry unix ts
}

// New creates an auth service backed by the JSON file at path, signing tokens
// with secret. Existing users are loaded from disk if the file is present.
func New(path string, secret []byte) (*Service, error) {
	s := &Service{
		users:     make(map[string]*storedUser),
		byUID:     make(map[string]*storedUser),
		path:      path,
		secret:    secret,
		hashCost:  DefaultBcryptCost,
		blacklist: make(map[string]blacklistEntry),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	go s.cleanBlacklist()
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
	var users []storedUser
	if err := json.Unmarshal(data, &users); err != nil {
		return err
	}
	for i := range users {
		u := &users[i]
		s.users[strings.ToLower(u.Email)] = u
		s.byUID[u.UID] = u
	}
	return nil
}

// save must be called with the write lock held.
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

// Register creates a new account and returns the user plus a fresh token.
func (s *Service) Register(email, password string) (*User, string, error) {
	email = strings.TrimSpace(email)
	if !emailRE.MatchString(email) || len(password) < 6 {
		return nil, "", ErrWeakInput
	}
	key := strings.ToLower(email)

	// Hash password before acquiring the lock — bcrypt is intentionally slow.
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.hashCost)
	if err != nil {
		return nil, "", fmt.Errorf("auth: hash password: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.users[key]; ok {
		return nil, "", ErrEmailTaken
	}

	u := &storedUser{
		User: User{
			UID:       randomHex(12),
			Email:     email,
			CreatedAt: time.Now().Unix(),
		},
		BCryptHash: string(hash),
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
// A dummy bcrypt comparison is always run to prevent timing-based user
// enumeration: a non-existent email takes the same time as a wrong password.
func (s *Service) Login(email, password string) (*User, string, error) {
	s.mu.RLock()
	u, ok := s.users[strings.ToLower(strings.TrimSpace(email))]
	s.mu.RUnlock()

	if !ok {
		// Constant-time dummy comparison prevents email enumeration via timing.
		_ = bcrypt.CompareHashAndPassword(
			[]byte("$2a$12$aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
			[]byte(password),
		)
		return nil, "", ErrInvalidCredentials
	}

	if err := bcrypt.CompareHashAndPassword([]byte(u.BCryptHash), []byte(password)); err != nil {
		return nil, "", ErrInvalidCredentials
	}

	token, err := s.issueToken(u)
	if err != nil {
		return nil, "", err
	}
	user := u.User
	return &user, token, nil
}

// Logout invalidates the token by adding its jti to the revocation blacklist.
// Subsequent Verify calls with the same token return ErrTokenRevoked.
func (s *Service) Logout(tokenStr string) error {
	claims, err := jwt.Parse(tokenStr, s.secret)
	if err != nil {
		return err
	}
	if claims.JWTID == "" {
		return nil
	}
	s.blackMu.Lock()
	s.blacklist[claims.JWTID] = blacklistEntry{expiresAt: claims.ExpiresAt}
	s.blackMu.Unlock()
	return nil
}

// Verify validates a bearer token, checks it against the revocation blacklist,
// and returns the associated user.
func (s *Service) Verify(tokenStr string) (*User, error) {
	claims, err := jwt.Parse(tokenStr, s.secret)
	if err != nil {
		return nil, err
	}

	if claims.JWTID != "" {
		s.blackMu.RLock()
		_, revoked := s.blacklist[claims.JWTID]
		s.blackMu.RUnlock()
		if revoked {
			return nil, ErrTokenRevoked
		}
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

func (s *Service) issueToken(u *storedUser) (string, error) {
	return jwt.Sign(jwt.Claims{
		Subject: u.UID,
		Email:   u.Email,
		JWTID:   randomHex(16),
	}, s.secret, tokenTTL)
}

// cleanBlacklist removes expired jti entries once per hour to bound memory use.
func (s *Service) cleanBlacklist() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now().Unix()
		s.blackMu.Lock()
		for jti, e := range s.blacklist {
			if now > e.expiresAt {
				delete(s.blacklist, jti)
			}
		}
		s.blackMu.Unlock()
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
