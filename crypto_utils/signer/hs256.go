package signer

import (
	"crypto"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/hmac"
	"github.com/imylam/modules-go/text_encoder"
)

const (
	ALGO                  = "HS256"
	ERR_INVALID_SIGNATURE = "invalid signature"
)

var hasher = crypto.SHA256

type SignerHS256 struct{}

func (s *SignerHS256) Algo() (algo string) {
	return ALGO
}

func (s *SignerHS256) SignScheme() (algo string) {
	return ALGO
}

func (s *SignerHS256) Sign(key, message string) (signature string, err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	signature, err = hmac.Sign(hasher, key, message, utf8Encoder, utf8Encoder, hexEncoder)

	return
}

func (s *SignerHS256) Verify(key, message, signature string) (err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	isValid, err := hmac.Verify(hasher, key, message, signature, utf8Encoder, utf8Encoder, hexEncoder)
	if err != nil {
		return
	}
	if !isValid {
		return errors.New(ERR_INVALID_SIGNATURE)
	}

	return nil
}
