package jwt_hs256

import (
	"crypto"

	"github.com/imylam/modules-go/jwt/signer/hmac"
)

const (
	ALGO = "HS256"
)

type JwtHS256 struct{}

func (s *JwtHS256) Algo() string {
	return ALGO
}

func (s *JwtHS256) SignScheme() string {
	return ALGO
}

func (s *JwtHS256) Sign(key, message string) (signature string, err error) {
	hasher := crypto.SHA256
	return hmac.Sign(hasher, key, message)
}

func (s *JwtHS256) Verify(key, message, signature string) (err error) {
	hasher := crypto.SHA256
	return hmac.Verify(hasher, key, message, signature)
}
