package rsa

import (
	"crypto"

	"github.com/imylam/modules-go/crypto_utils/rsa"
	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/text_encoder"
)

func Sign(hasher crypto.Hash, signScheme sign_scheme.RsaSignScheme,
	privateKey, message string, keyParser key_parser.RsaPrivateKeyParser) (signature string, err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}

	return rsa.Sign(hasher, signScheme, privateKey, message, keyParser, utf8Encoder, b64RawUrlEncoder)
}

func Verify(hasher crypto.Hash, signScheme sign_scheme.RsaSignScheme,
	publicKey, message, signature string, keyParser key_parser.RsaPublicKeyParser) (err error) {
	utf8Encoder := &text_encoder.Utf8Encoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}

	return rsa.Verify(hasher, signScheme, publicKey, message, signature, keyParser, utf8Encoder, b64RawUrlEncoder)
}
