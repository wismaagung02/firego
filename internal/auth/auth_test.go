package auth

import (
	"path/filepath"
	"testing"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "users.json"), []byte("test-secret"))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
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
