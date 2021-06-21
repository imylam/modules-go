package rsa

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/text_encoder"
)

const (
	keySize = 2048

	ErrDecodeCipherText = "failed to decode cipher text: "
	ErrDecodeMsg        = "failed to decode message: "
	ErrDecodePlainText  = "failed to decode plain text: "
	ErrDecodeSignature  = "failed to decode signature: "
)

// GenerateKeyPair generates a 2048 RSA Key Pair, and return both the private and public keys as pem string
func GenerateKeyPair(priKeyParser key_parser.RsaPrivateKeyParser,
	pubKeyParser key_parser.RsaPublicKeyParser) (privateKeyPem, publicKeyPem string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return
	}

	err = privateKey.Validate()
	if err != nil {
		return
	}

	privateKeyPem, err = priKeyParser.MarshalPrivateKeyAsPemStr(privateKey)
	if err != nil {
		return
	}

	publicKeyPem, err = pubKeyParser.MarshalPublicKeyAsPemStr(&privateKey.PublicKey)
	return
}

// Encrypt plainText with PublicKey using RSA-OAEP
func Encrypt(hash crypto.Hash, publicKeyPem, plainText string, keyParser key_parser.RsaPublicKeyParser,
	plainTextEncoder, cipherTextEncoder text_encoder.Encoder) (cipherText string, err error) {
	plainTextByte, err := plainTextEncoder.Decode(plainText)
	if err != nil {
		err = errors.New(ErrDecodePlainText + err.Error())
		return
	}
	publicKey, err := keyParser.ParsePublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		return
	}

	rng := rand.Reader
	cipherTextBytes, err := rsa.EncryptOAEP(hash.New(), rng, publicKey, plainTextByte, nil)
	if err != nil {
		return
	}

	cipherText = cipherTextEncoder.Encode(cipherTextBytes)
	return
}

// Decrypt cipherText with PrivateKey using RSA-OAEP
func Decrypt(hash crypto.Hash, privateKeyPem, cipherText string, keyParser key_parser.RsaPrivateKeyParser,
	cipherTextEncoder, plainTextEncoder text_encoder.Encoder) (plainText string, err error) {
	cipherTextBytes, err := cipherTextEncoder.Decode(cipherText)
	if err != nil {
		err = errors.New(ErrDecodeCipherText + err.Error())
		return
	}
	privateKey, err := keyParser.ParsePrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return
	}

	rng := rand.Reader
	plainTextBytes, err := rsa.DecryptOAEP(hash.New(), rng, privateKey, cipherTextBytes, nil)
	if err != nil {
		return
	}

	plainText = plainTextEncoder.Encode(plainTextBytes)
	return
}

// Sign a message with PrivateKey using RSA-PSS and the crypto hash given
func Sign(hash crypto.Hash, signScheme sign_scheme.RsaSignScheme, privateKeyPem, message string,
	keyParser key_parser.RsaPrivateKeyParser, messageEncoder, signatureEncoder text_encoder.Encoder) (signature string, err error) {
	privateKey, err := keyParser.ParsePrivateKeyFromPemStr(privateKeyPem)
	if err != nil {
		return
	}

	messageByte, err := messageEncoder.Decode(message)
	if err != nil {
		err = errors.New(ErrDecodeMsg + err.Error())
		return
	}
	hasher := hash.New()
	hasher.Write(messageByte)
	hashedMessage := hasher.Sum(nil)

	signatureBytes, err := signScheme.Sign(hash, privateKey, hashedMessage)
	signature = signatureEncoder.Encode(signatureBytes)
	return
}

// Verify a signature with PublicKey using RSA-PSS and the crypto hash given
func Verify(hash crypto.Hash, signScheme sign_scheme.RsaSignScheme, publicKeyPem, message, signature string,
	keyParser key_parser.RsaPublicKeyParser, messageEncoder, signatureEncoder text_encoder.Encoder) (err error) {
	publicKey, err := keyParser.ParsePublicKeyFromPemStr(publicKeyPem)
	if err != nil {
		return
	}

	messageByte, err := messageEncoder.Decode(message)
	if err != nil {
		err = errors.New(ErrDecodeMsg + err.Error())
		return
	}
	hasher := hash.New()
	hasher.Write(messageByte)
	hashedMessageBytes := hasher.Sum(nil)

	signatureBytes, err := signatureEncoder.Decode(signature)
	if err != nil {
		err = errors.New(ErrDecodeSignature + err.Error())
		return err
	}
	return signScheme.Verify(hash, publicKey, hashedMessageBytes, signatureBytes)
}
