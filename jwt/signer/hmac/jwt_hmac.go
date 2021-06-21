package hmac

import (
	"crypto"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/hmac"
	"github.com/imylam/modules-go/text_encoder"
)

const (
	ERR_INVALID_SIGNATURE = "invalid signature"
)

func Sign(hasher crypto.Hash, key, message string) (signature string, err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}

	signature, err = hmac.Sign(hasher, key, message, utf8Encoder, utf8Encoder, b64RawUrlEncoder)

	return
}

func Verify(hasher crypto.Hash, key, message, signature string) (err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}

	isValid, err := hmac.Verify(hasher, key, message, signature, utf8Encoder, utf8Encoder, b64RawUrlEncoder)
	if err != nil {
		return
	}
	if !isValid {
		return errors.New(ERR_INVALID_SIGNATURE)
	}

	return nil
}
