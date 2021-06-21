package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
)

type PkixPublicKeyParser struct{}

// MarshalPublicKeyAsPemStr marshals *rsa.PublicKey to an x509 PublicKeyPem string using PKIX
func (p *PkixPublicKeyParser) MarshalPublicKeyAsPemStr(publicKey *rsa.PublicKey) (publicKeyPem string, err error) {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return
	}

	publicKeyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	publicKeyPem = string(publicKeyPemBytes)
	return
}

// ParsePublicKeyFromPemStrs parse an x509 PKIX PublicKeyPem string to *rsa.PublicKey
func (p *PkixPublicKeyParser) ParsePublicKeyFromPemStr(publicKeyPem string) (publicKey *rsa.PublicKey, err error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New(key_parser.ERR_PARSE_PUBLIC_KEY)
	}

	result, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	publicKey, ok := result.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New(key_parser.ERR_NOT_RSA_PUBLIC_KEY)
	}

	return
}
