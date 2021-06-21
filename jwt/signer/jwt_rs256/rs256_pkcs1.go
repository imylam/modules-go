package jwt_rs256

import (
	"crypto"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser/x509"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	jwt_rsa "github.com/imylam/modules-go/jwt/signer/rsa"
)

type jwtRS256Pkcs1 struct {
	signScheme sign_scheme.RsaSignScheme
}

func NewJwtRS256Pkcs1() *jwtRS256Pkcs1 {
	return &jwtRS256Pkcs1{signScheme: sign_scheme.NewRsaSignPKCSv1_5()}
}

func (s *jwtRS256Pkcs1) Algo() (algo string) {
	return ALGO
}

func (s *jwtRS256Pkcs1) SignScheme() (algo string) {
	return s.signScheme.SignScheme()
}

func (s *jwtRS256Pkcs1) Sign(privateKey, message string) (signature string, err error) {
	hasher := crypto.SHA256
	keyParser := &x509.Pkcs1Parser{}
	return jwt_rsa.Sign(hasher, s.signScheme, privateKey, message, keyParser)
}

func (s *jwtRS256Pkcs1) Verify(publicKey, message, signature string) (err error) {
	hasher := crypto.SHA256
	keyParser := &x509.Pkcs1Parser{}
	return jwt_rsa.Verify(hasher, s.signScheme, publicKey, message, signature, keyParser)
}
