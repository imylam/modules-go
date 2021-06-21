package key_parser

import (
	"crypto/rsa"
)

const (
	ERR_NOT_RSA_PRIVATE_KEY = "not a rsa private key"
	ERR_NOT_RSA_PUBLIC_KEY  = "not a rsa public key"
	ERR_PARSE_PRIVATE_KEY   = "failed to parse PEM block containing the private key"
	ERR_PARSE_PUBLIC_KEY    = "failed to parse PEM block containing the public key"
)

type RsaPrivateKeyParser interface {
	MarshalPrivateKeyAsPemStr(*rsa.PrivateKey) (string, error)
	ParsePrivateKeyFromPemStr(string) (*rsa.PrivateKey, error)
}

type RsaPublicKeyParser interface {
	MarshalPublicKeyAsPemStr(*rsa.PublicKey) (string, error)
	ParsePublicKeyFromPemStr(publicKeyPem string) (*rsa.PublicKey, error)
}
