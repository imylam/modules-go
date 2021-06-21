package x509

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
)

type Pkcs8PrivateKeyParser struct{}

// MarshalPrivateKeyAsPemStr marshals *rsa.PrivateKey to an x509 PrivateKeyPem string using PKCS8 padding
func (p *Pkcs8PrivateKeyParser) MarshalPrivateKeyAsPemStr(privateKey *rsa.PrivateKey) (privateKeyPem string, err error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return
	}

	privkeyPemBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privKeyBytes,
		},
	)
	privateKeyPem = string(privkeyPemBytes)
	return
}

// ParsePrivateKeyFromPemStr parses an x509 PKCS8 PrivateKeyPem string to *rsa.PrivateKey
func (p *Pkcs8PrivateKeyParser) ParsePrivateKeyFromPemStr(privatePem string) (privateKey *rsa.PrivateKey, err error) {
	block, _ := pem.Decode([]byte(privatePem))
	if block == nil {
		err = errors.New(key_parser.ERR_PARSE_PRIVATE_KEY)
		return
	}

	result, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return
	}

	privateKey, ok := result.(*rsa.PrivateKey)
	if !ok {
		err = errors.New(key_parser.ERR_NOT_RSA_PRIVATE_KEY)
	}

	return
}
