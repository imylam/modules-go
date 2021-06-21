package jwt_hs512

import (
	"crypto"

	"github.com/imylam/modules-go/jwt/signer/hmac"
)

const (
	ALGO = "HS512"
)

type JwtHS512 struct{}

func (s *JwtHS512) Algo() (algo string) {
	return ALGO
}

func (s *JwtHS512) SignScheme() (algo string) {
	return ALGO
}

func (s *JwtHS512) Sign(key, message string) (signature string, err error) {
	hasher := crypto.SHA512
	return hmac.Sign(hasher, key, message)
}

func (s *JwtHS512) Verify(key, message, signature string) (err error) {
	hasher := crypto.SHA512
	return hmac.Verify(hasher, key, message, signature)
}
