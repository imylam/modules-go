package sign_scheme

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
)

const (
	PKCSv1_5 = "PKCSv1_5"
)

type rsaSignPKCSv1_5 struct {
	signScheme string
}

func NewRsaSignPKCSv1_5() *rsaSignPKCSv1_5 {
	return &rsaSignPKCSv1_5{signScheme: PKCSv1_5}
}

func (s *rsaSignPKCSv1_5) SignScheme() string {
	return s.signScheme
}

func (s *rsaSignPKCSv1_5) Sign(hash crypto.Hash, privateKey *rsa.PrivateKey,
	hashedMessageBytes []byte) (signatureByte []byte, err error) {
	rng := rand.Reader

	signatureByte, err = rsa.SignPKCS1v15(rng, privateKey, hash, hashedMessageBytes)
	if err != nil {
		return
	}

	return
}

func (s *rsaSignPKCSv1_5) Verify(hash crypto.Hash, publicKey *rsa.PublicKey,
	hashedMessageBytes, signatureBytes []byte) error {

	return rsa.VerifyPKCS1v15(publicKey, hash, hashedMessageBytes, signatureBytes)
}
