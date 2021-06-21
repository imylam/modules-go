package jwt_rs512

import (
	"crypto"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser/x509"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	jwt_rsa "github.com/imylam/modules-go/jwt/signer/rsa"
)

type jwtRS512Pkcs1Pkix struct {
	signScheme sign_scheme.RsaSignScheme
}

func NewJwtRS512Pkcs1Pkix() *jwtRS512Pkcs1Pkix {
	return &jwtRS512Pkcs1Pkix{signScheme: sign_scheme.NewRsaSignPKCSv1_5()}
}

func (s *jwtRS512Pkcs1Pkix) Algo() (algo string) {
	return ALGO
}

func (s *jwtRS512Pkcs1Pkix) SignScheme() (algo string) {
	return s.signScheme.SignScheme()
}

func (s *jwtRS512Pkcs1Pkix) Sign(privateKey, message string) (signature string, err error) {
	hasher := crypto.SHA512
	privateKeyParser := &x509.Pkcs1Parser{}
	return jwt_rsa.Sign(hasher, s.signScheme, privateKey, message, privateKeyParser)
}

func (s *jwtRS512Pkcs1Pkix) Verify(publicKey, message, signature string) (err error) {
	hasher := crypto.SHA512
	publicKeyParser := &x509.PkixPublicKeyParser{}
	return jwt_rsa.Verify(hasher, s.signScheme, publicKey, message, signature, publicKeyParser)
}
