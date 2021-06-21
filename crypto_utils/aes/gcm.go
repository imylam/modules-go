package aes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/imylam/modules-go/text_encoder"
)

// Constants
const (
	KeySize           = 32
	KeyStringLength   = 44
	NonceStringLength = 16

	ErrorCipherTextNotMultipleOfBlockSize = "Ciphertext is not a multiple of the block size"
	ErrorCipherTextTooShort               = "Cipher text too short"
	ErrFailureToDecodeCipherTextStr       = "failed to decode cipher text: "
	ErrFailureToDecodeKeyStr              = "failed to decode key: "
	ErrFailureToDecodePlainTextStr        = "failed to decode plain text: "
	ErrInvalidBlockSize                   = "invalid blocksize"
	ErrInvalidKeySize                     = "key size should be 32"
	ErrInvalidNonceSize                   = "nonce size should be 12"
	ErrPlainTextNotMultipleOfBlockSize    = "plaintext is not a multiple of the block size" // ErrInvalidBlockSize indicates hash blocksize <= 0
	ErrEmptyOrNotPaddedPKCS7Data          = "invalid PKCS7 data (empty or not padded)"      // ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Padding                = "invalid padding on input"                      // ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input
)

// NewKey creates a 32 bytes AES-GCM key
func NewKey(keyEncoder text_encoder.Encoder) (key string, err error) {
	keyBytes := make([]byte, KeySize)
	if _, err := rand.Read(keyBytes); err != nil {
		return "", err
	}

	return keyEncoder.Encode(keyBytes), nil
}

func NewAesCipher(key string, keyEncoder text_encoder.Encoder) (block cipher.Block, err error) {
	keyBytes, err := keyEncoder.Decode(key)
	if err != nil {
		return nil, errors.New(ErrFailureToDecodeKeyStr + err.Error())
	}

	block, err = aes.NewCipher(keyBytes)
	if err != nil {
		return nil, err
	}

	return
}

// Encrypt plainText using AES CBC mode
func EncryptCBC(block cipher.Block, plainText string, plainTextEncoder, cipherTextEncoder text_encoder.Encoder) (cipherText string, err error) {
	plainTextBytes, err := plainTextEncoder.Decode(plainText)
	if err != nil {
		return "", errors.New(ErrFailureToDecodePlainTextStr + err.Error())
	}

	paddedPlainTextBytes, err := pkcs7Pad(plainTextBytes, block.BlockSize())
	if err != nil {
		return "", err
	}
	if len(paddedPlainTextBytes)%aes.BlockSize != 0 {
		return "", errors.New(ErrPlainTextNotMultipleOfBlockSize)
	}

	cipherTextBytes := make([]byte, aes.BlockSize+len(paddedPlainTextBytes))
	iv := cipherTextBytes[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherTextBytes[aes.BlockSize:], paddedPlainTextBytes)
	cipherText = cipherTextEncoder.Encode(cipherTextBytes)

	return
}

// Decrypt cipherText using AES CBC mode
func DecryptCBC(block cipher.Block, cipherText string, cipherTextEncoder, plainTextEncoder text_encoder.Encoder) (plainText string, err error) {
	cipherTextBytes, err := cipherTextEncoder.Decode(cipherText)
	if err != nil {
		return "", errors.New(ErrFailureToDecodeCipherTextStr + err.Error())
	}
	if len(cipherTextBytes) < aes.BlockSize {
		return "", errors.New(ErrorCipherTextTooShort)
	}

	iv := cipherTextBytes[:aes.BlockSize]
	cipherTextBytes = cipherTextBytes[aes.BlockSize:]

	// CBC mode always works in whole blocks.
	if len(cipherTextBytes)%aes.BlockSize != 0 {
		return "", errors.New(ErrorCipherTextNotMultipleOfBlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherTextBytes, cipherTextBytes)

	cipherTextBytes, err = pkcs7Unpad(cipherTextBytes, block.BlockSize())
	if err != nil {
		return "", err
	}
	plainText = plainTextEncoder.Encode(cipherTextBytes)

	return
}

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New(ErrInvalidBlockSize)
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New(ErrEmptyOrNotPaddedPKCS7Data)
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New(ErrInvalidBlockSize)
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New(ErrEmptyOrNotPaddedPKCS7Data)
	}
	if len(b)%blocksize != 0 {
		return nil, errors.New(ErrInvalidPKCS7Padding)
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, errors.New(ErrInvalidPKCS7Padding)
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, errors.New(ErrInvalidPKCS7Padding)
		}
	}
	return b[:len(b)-n], nil
}
