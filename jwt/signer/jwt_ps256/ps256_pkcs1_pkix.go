package jwt_ps256

import (
	"crypto"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser/x509"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	jwt_rsa "github.com/imylam/modules-go/jwt/signer/rsa"
)

type jwtPS256Pkcs1Pkix struct {
	signScheme sign_scheme.RsaSignScheme
}

func NewJwtPS256Pkcs1Pkix() *jwtPS256Pkcs1Pkix {
	return &jwtPS256Pkcs1Pkix{signScheme: sign_scheme.NewRsaSignPss()}
}

func (s *jwtPS256Pkcs1Pkix) Algo() (algo string) {
	return ALGO
}

func (s *jwtPS256Pkcs1Pkix) SignScheme() (algo string) {
	return s.signScheme.SignScheme()
}

func (s *jwtPS256Pkcs1Pkix) Sign(privateKey, message string) (signature string, err error) {
	hasher := crypto.SHA256
	privateKeyParser := &x509.Pkcs1Parser{}
	return jwt_rsa.Sign(hasher, s.signScheme, privateKey, message, privateKeyParser)
}

func (s *jwtPS256Pkcs1Pkix) Verify(publicKey, message, signature string) (err error) {
	hasher := crypto.SHA256
	publicKeyParser := &x509.PkixPublicKeyParser{}
	return jwt_rsa.Verify(hasher, s.signScheme, publicKey, message, signature, publicKeyParser)
}
