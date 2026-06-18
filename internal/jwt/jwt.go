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
// claims (sub, exp, iat) are kept alongside arbitrary custom fields.
type Claims struct {
	Subject   string         `json:"sub,omitempty"`
	Email     string         `json:"email,omitempty"`
	IssuedAt  int64          `json:"iat,omitempty"`
	ExpiresAt int64          `json:"exp,omitempty"`
	Extra     map[string]any `json:"-"`
}

func b64encode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func sign(signingInput string, secret []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return b64encode(mac.Sum(nil))
}

// Sign creates a signed token for the given claims, valid for ttl.
func Sign(claims Claims, secret []byte, ttl time.Duration) (string, error) {
	now := time.Now()
	claims.IssuedAt = now.Unix()
	claims.ExpiresAt = now.Add(ttl).Unix()

	headerJSON, err := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := b64encode(headerJSON) + "." + b64encode(claimsJSON)
	signature := sign(signingInput, secret)
	return signingInput + "." + signature, nil
}

// Parse verifies a token's signature and expiry, returning its claims.
func Parse(token string, secret []byte) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	signingInput := parts[0] + "." + parts[1]
	expected := sign(signingInput, secret)
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return nil, ErrInvalidToken
	}

	claimsJSON, err := b64decode(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if claims.ExpiresAt != 0 && time.Now().Unix() > claims.ExpiresAt {
		return nil, ErrInvalidToken
	}
	return &claims, nil
}
