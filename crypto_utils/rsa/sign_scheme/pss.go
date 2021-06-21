package sign_scheme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	PSS = "PSS"
)

type rsaSignPss struct {
	signScheme string
}

func NewRsaSignPss() *rsaSignPss {
	return &rsaSignPss{signScheme: PSS}
}

func (s *rsaSignPss) SignScheme() string {
	return s.signScheme
}

func (s *rsaSignPss) Sign(hash crypto.Hash, privateKey *rsa.PrivateKey,
	hashedMessageBytes []byte) (signatureByte []byte, err error) {
	rng := rand.Reader

	signatureByte, err = rsa.SignPSS(rng, privateKey, hash, hashedMessageBytes, nil)
	if err != nil {
		return
	}

	return
}

func (s *rsaSignPss) Verify(hash crypto.Hash, publicKey *rsa.PublicKey,
	hashedMessageBytes, signatureBytes []byte) error {
	return rsa.VerifyPSS(publicKey, hash, hashedMessageBytes, signatureBytes, nil)
}
