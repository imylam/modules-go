package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
)

type Pkcs1Parser struct{}

// marshalPrivateKeyAsPemStr marshals *rsa.PrivateKey to an x509 PrivateKeyPem string using PKCS1 padding
func (p *Pkcs1Parser) MarshalPrivateKeyAsPemStr(privateKey *rsa.PrivateKey) (string, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privkeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	return string(privkeyPem), nil
}

// parsePrivateKeyFromPemStr parses an x509 PrivateKeyPem string to *rsa.PrivateKey
func (p *Pkcs1Parser) ParsePrivateKeyFromPemStr(privatePem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privatePem))
	if block == nil {
		return nil, errors.New(key_parser.ERR_PARSE_PRIVATE_KEY)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// MarshalPublicKeyAsPemStr marshals *rsa.PublicKe to an x509 PublicKeyPem string using PKCS1 padding
func (p *Pkcs1Parser) MarshalPublicKeyAsPemStr(publicKey *rsa.PublicKey) (string, error) {
	publicKeyBytes := x509.MarshalPKCS1PublicKey(publicKey)
	publicKeyPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return string(publicKeyPem), nil
}

// ParsePublicKeyFromPemStrs parse an x509 PublicKeyPem string to *rsa.PublicKey
func (p *Pkcs1Parser) ParsePublicKeyFromPemStr(publicKeyPem string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPem))
	if block == nil {
		return nil, errors.New(key_parser.ERR_PARSE_PUBLIC_KEY)
	}

	publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}
