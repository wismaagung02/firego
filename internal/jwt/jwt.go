// Package jwt provides a minimal JWT (JSON Web Token) implementation using
// HMAC-SHA256, relying only on the Go standard library.
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// ErrInvalidToken is returned when a token is malformed, has a bad signature,
// or has expired.
var ErrInvalidToken = errors.New("jwt: invalid token")

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims is the set of values carried inside a token. Standard registered
// claims (sub, exp, iat, jti) are kept alongside optional custom fields.
type Claims struct {
	Subject   string `json:"sub,omitempty"`
	Email     string `json:"email,omitempty"`
	JWTID     string `json:"jti,omitempty"` // unique token ID used for revocation
	IssuedAt  int64  `json:"iat,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
}

func b64encode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func b64decode(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }

func sign(input string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return b64encode(mac.Sum(nil))
}

// Sign creates a signed token for the given claims, valid for ttl.
func Sign(claims Claims, secret []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()

	hJSON, err := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	cJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	si := b64encode(hJSON) + "." + b64encode(cJSON)
	return si + "." + sign(si, secret), nil
}

// Parse verifies a token's signature and expiry, returning its claims.
func Parse(token string, secret []byte) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	si := parts[0] + "." + parts[1]
	expected := sign(si, secret)
	// constant-time comparison prevents timing oracle on the signature
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, ErrInvalidToken
	}

	cJSON, err := b64decode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var c Claims
	if err := json.Unmarshal(cJSON, &c); err != nil {
		return nil, ErrInvalidToken
	}
	now := time.Now().Unix()
	if c.IssuedAt > now+30 { // allow 30 s clock skew, reject future-issued tokens
		return nil, ErrInvalidToken
	}
	if c.ExpiresAt != 0 && now > c.ExpiresAt {
		return nil, ErrInvalidToken
	}
	return &c, nil
}
