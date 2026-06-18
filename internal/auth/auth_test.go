package auth

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "users.json"), []byte("test-secret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Use minimum bcrypt cost so tests run fast.
	s.hashCost = bcrypt.MinCost
	return s
}

func TestRegisterAndLogin(t *testing.T) {
	s := newTestService(t)
	user, token, err := s.Register("bob@example.com", "secret123")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.UID == "" || token == "" {
		t.Fatal("expected uid and token")
	}

	if _, _, err := s.Login("bob@example.com", "secret123"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, _, err := s.Login("bob@example.com", "wrong"); err != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials, got %v", err)
	}
}

func TestDuplicateEmail(t *testing.T) {
	s := newTestService(t)
	_, _, _ = s.Register("dup@example.com", "secret123")
	if _, _, err := s.Register("dup@example.com", "another1"); err != ErrEmailTaken {
		t.Fatalf("expected ErrEmailTaken, got %v", err)
	}
}

func TestWeakInput(t *testing.T) {
	s := newTestService(t)
	if _, _, err := s.Register("", "secret123"); err != ErrWeakInput {
		t.Fatalf("expected ErrWeakInput for empty email, got %v", err)
	}
	if _, _, err := s.Register("notanemail", "secret123"); err != ErrWeakInput {
		t.Fatalf("expected ErrWeakInput for invalid email, got %v", err)
	}
	if _, _, err := s.Register("a@b.com", "123"); err != ErrWeakInput {
		t.Fatalf("expected ErrWeakInput for short password, got %v", err)
	}
}

func TestVerifyToken(t *testing.T) {
	s := newTestService(t)
	_, token, _ := s.Register("v@example.com", "secret123")

	user, err := s.Verify(token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if user.Email != "v@example.com" {
		t.Fatalf("got %s", user.Email)
	}
	if _, err := s.Verify("garbage.token.here"); err == nil {
		t.Fatal("expected error for invalid token")
	}
}

func TestLogout(t *testing.T) {
	s := newTestService(t)
	_, token, _ := s.Register("logout@example.com", "secret123")

	// Token works before logout.
	if _, err := s.Verify(token); err != nil {
		t.Fatalf("Verify before logout: %v", err)
	}

	if err := s.Logout(token); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Same token must be rejected after logout.
	if _, err := s.Verify(token); err != ErrTokenRevoked {
		t.Fatalf("expected ErrTokenRevoked, got %v", err)
	}
}

func TestUserEnumerationProtection(t *testing.T) {
	s := newTestService(t)
	_, _, _ = s.Register("real@example.com", "secret123")

	// Both non-existent email and wrong password must return the same error.
	_, _, err1 := s.Login("nope@example.com", "anypass")
	_, _, err2 := s.Login("real@example.com", "wrongpass")
	if err1 != ErrInvalidCredentials || err2 != ErrInvalidCredentials {
		t.Fatalf("expected ErrInvalidCredentials for both, got %v / %v", err1, err2)
	}
}
