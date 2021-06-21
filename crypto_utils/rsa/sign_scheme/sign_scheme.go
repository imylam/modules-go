package sign_scheme

import (
	"crypto"
	"crypto/rsa"
)

type RsaSignScheme interface {
	SignScheme() string
	Sign(crypto.Hash, *rsa.PrivateKey, []byte) ([]byte, error)
	Verify(crypto.Hash, *rsa.PublicKey, []byte, []byte) error
}
