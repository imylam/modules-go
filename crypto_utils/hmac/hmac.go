package hmac

import (
	"crypto"
	"errors"

	"crypto/hmac"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/sha3"

	"github.com/imylam/modules-go/text_encoder"
)

const (
	ErrDecodeMsg       = "failed to decode message: "
	ErrDecodeKey       = "failed to decode key: "
	ErrDecodeSignature = "failed to decode signature: "
)

func Sign(hasher crypto.Hash, key, message string, keyEncoder, msgEncoder,
	signatureEncoder text_encoder.Encoder) (signature string, err error) {
	msgBytes, err := msgEncoder.Decode(message)
	if err != nil {
		err = errors.New(ErrDecodeMsg + err.Error())
		return
	}
	keyBytes, err := keyEncoder.Decode(key)
	if err != nil {
		err = errors.New(ErrDecodeKey + err.Error())
		return
	}

	hash := hmac.New(hasher.HashFunc().New, keyBytes)
	hash.Write(msgBytes)
	signature = signatureEncoder.Encode(hash.Sum(nil))

	return
}

func Verify(hasher crypto.Hash, key, message, signature string, keyEncoder, msgEncoder,
	signatureEncoder text_encoder.Encoder) (isSignatureValid bool, err error) {
	messageBytes, err := msgEncoder.Decode(message)
	if err != nil {
		err = errors.New(ErrDecodeMsg + err.Error())
		return
	}
	keyBytes, err := keyEncoder.Decode(key)
	if err != nil {
		err = errors.New(ErrDecodeKey + err.Error())
		return
	}
	signatureBytes, err := signatureEncoder.Decode(signature)
	if err != nil {
		err = errors.New(ErrDecodeSignature + err.Error())
	}

	hash := hmac.New(hasher.HashFunc().New, keyBytes)
	hash.Write(messageBytes)
	expectedSignature := hash.Sum(nil)

	return hmac.Equal(signatureBytes, expectedSignature), err
}
