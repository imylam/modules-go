package aes

import (
	"bytes"
	cryptoRand "crypto/rand"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"github.com/imylam/modules-go/text_encoder"
)

func Test_NewKey(t *testing.T) {
	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	b64StdKey, _ := NewKey(b64StdEncoder)
	b64RawStdKey, _ := NewKey(b64RawStdEncoder)
	b64RawUrlKey, _ := NewKey(b64RawUrlEncoder)
	hexKey, _ := NewKey(hexEncoder)
	utf8Key, _ := NewKey(utf8Encoder)

	b64StdBytes, err := b64StdEncoder.Decode(b64StdKey)
	if err != nil {
		t.Errorf("Expect err to be nil, got: %s", err.Error())
	}

	b64RawStdBytes, err := b64RawStdEncoder.Decode(b64RawStdKey)
	if err != nil {
		t.Errorf("Expect err to be nil, got: %s", err.Error())
	}

	b64RawUrlBytes, err := b64RawUrlEncoder.Decode(b64RawUrlKey)
	if err != nil {
		t.Errorf("Expect err to be nil, got: %s", err.Error())
	}

	hexBytes, err := hexEncoder.Decode(hexKey)
	if err != nil {
		t.Errorf("Expect err to be nil, got: %s", err.Error())
	}

	utf8Bytes, err := utf8Encoder.Decode(utf8Key)
	if err != nil {
		t.Errorf("Expect err to be nil, got: %s", err.Error())
	}

	if len(b64StdBytes) != KeySize {
		t.Errorf("Failed, expect key size: %d, got: %d", KeySize, len(b64StdBytes))
	}
	if len(b64RawStdBytes) != KeySize {
		t.Errorf("Failed, expect key size: %d, got: %d", KeySize, len(b64RawStdBytes))
	}
	if len(b64RawUrlBytes) != KeySize {
		t.Errorf("Failed, expect key size: %d, got: %d", KeySize, len(b64RawUrlBytes))
	}
	if len(hexBytes) != KeySize {
		t.Errorf("Failed, expect key size: %d, got: %d", KeySize, len(hexBytes))
	}
	if len(utf8Bytes) != KeySize {
		t.Errorf("Failed, expect key size: %d, got: %d", KeySize, len(utf8Bytes))
	}
}

func Test_NewAesCipher(t *testing.T) {
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	utf8Key, _ := NewKey(utf8Encoder)

	t.Run("GIVEN_invalid-key-encoder_WHEN_creating-new-cipher_THEN_throw_err", func(t *testing.T) {
		cipher, err := NewAesCipher(utf8Key, hexEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrFailureToDecodeKeyStr) {
			t.Errorf("Expected error msg contains: %s, got %s", ErrFailureToDecodeKeyStr, err.Error())
		}
		if cipher != nil {
			t.Errorf("Expected cipher to be nil")
		}
	})

	t.Run("GIVEN_invalid-key-size_creating-new-cipher_THEN_throw_err", func(t *testing.T) {
		expectedErrMsg := "crypto/aes: invalid key size"
		cipher, err := NewAesCipher("key", utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Expected error msg contains: %s, got %s", expectedErrMsg, err.Error())
		}
		if cipher != nil {
			t.Errorf("Expected cipher to be nil")
		}
	})
}

func Test_EncryptCBC(t *testing.T) {
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}
	key, _ := NewKey(utf8Encoder)
	aes, _ := NewAesCipher(key, utf8Encoder)

	t.Run("GIVEN_empty-plainText_WHEN_encrypting_THEN_throw_err", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, "", utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrEmptyOrNotPaddedPKCS7Data) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrEmptyOrNotPaddedPKCS7Data, err.Error())
		}
		if cipherText != "" {
			t.Errorf("Expected empty strint, got: %s", cipherText)
		}
	})

	t.Run("GIVEN_invalid-plainText-encoder_WHEN_encrypting_THEN_throw_err", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, "plainText", hexEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrFailureToDecodePlainTextStr) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrFailureToDecodePlainTextStr, err.Error())
		}
		if cipherText != "" {
			t.Errorf("Expected empty strint, got: %s", cipherText)
		}
	})
}

func Test_DecryptCBC(t *testing.T) {
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}
	key, _ := NewKey(utf8Encoder)
	aes, _ := NewAesCipher(key, utf8Encoder)

	t.Run("GIVEN_invalid-cipherText-encoder_WHEN_decrypting_THEN_throw_err", func(t *testing.T) {
		cipherText, _ := EncryptCBC(aes, "plainText", utf8Encoder, utf8Encoder)
		plainText, err := DecryptCBC(aes, cipherText, hexEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrFailureToDecodeCipherTextStr) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrFailureToDecodeCipherTextStr, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected empty plainText: got: %s", plainText)
		}
	})

	t.Run("GIVEN_cipherText-too-short_WHEN_decrypting_THEN_throw_err", func(t *testing.T) {
		plainText, err := DecryptCBC(aes, "hello", utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrorCipherTextTooShort {
			t.Errorf("Expected err message: %s, got: %s", ErrorCipherTextTooShort, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected empty plainText: got: %s", plainText)
		}
	})

	t.Run("GIVEN_cipherText-not-multiple-of-blockSize_WHEN_decrypting_THEN_throw_err", func(t *testing.T) {
		plainText, err := DecryptCBC(aes, string(randomBytesOfLength(20)), utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrorCipherTextNotMultipleOfBlockSize {
			t.Errorf("Expected err message: %s, got: %s", ErrorCipherTextNotMultipleOfBlockSize, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected empty plainText: got: %s", plainText)
		}
	})

	t.Run("GIVEN_invalid-pkcs7-cipherText_WHEN_decrypting_THEN_throw_err", func(t *testing.T) {
		byteArr := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		plainText, err := DecryptCBC(aes, string(byteArr), utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrEmptyOrNotPaddedPKCS7Data {
			t.Errorf("Expected err message: %s, got: %s", ErrEmptyOrNotPaddedPKCS7Data, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected empty plainText: got: %s", plainText)
		}
	})
}

func Test_EncryptThenDecryptCBC(t *testing.T) {
	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	// Create test plainText randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)
	b64StdPlainText := b64StdEncoder.Encode(input)
	b64RawStdPlainText := b64RawStdEncoder.Encode(input)
	b64RawUrlPlainText := b64RawUrlEncoder.Encode(input)
	hexPlainText := hexEncoder.Encode(input)
	utf8PlainText := utf8Encoder.Encode(input)

	key, _ := NewKey(b64StdEncoder)
	aes, _ := NewAesCipher(key, b64StdEncoder)

	t.Run("success-b64Std", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, b64StdPlainText, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		plainText, err := DecryptCBC(aes, cipherText, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		if plainText != b64StdPlainText {
			t.Errorf("Failed, expect plainText: %s, got: %s", b64StdPlainText, plainText)
		}
	})

	t.Run("success-b64RawStd", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, b64RawStdPlainText, b64RawStdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		plainText, err := DecryptCBC(aes, cipherText, b64RawStdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		if plainText != b64RawStdPlainText {
			t.Errorf("Failed, expect: %s, got: %s", b64RawStdPlainText, plainText)
		}
	})

	t.Run("success-b64RawUrl", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, b64RawUrlPlainText, b64RawUrlEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		plainText, err := DecryptCBC(aes, cipherText, b64RawUrlEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		if plainText != b64RawUrlPlainText {
			t.Errorf("Failed, expect: %s, got: %s", b64RawUrlPlainText, plainText)
		}
	})

	t.Run("success-hex", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, hexPlainText, hexEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		plainText, err := DecryptCBC(aes, cipherText, hexEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		if plainText != hexPlainText {
			t.Errorf("Failed, expect: %s, got: %s", hexPlainText, plainText)
		}
	})

	t.Run("success-utf8", func(t *testing.T) {
		cipherText, err := EncryptCBC(aes, utf8PlainText, utf8Encoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		plainText, err := DecryptCBC(aes, cipherText, utf8Encoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expected nil error, got: %s", err.Error())
		}

		if plainText != utf8PlainText {
			t.Errorf("Failed, expect: %s, got: %s", utf8PlainText, plainText)
		}
	})

	t.Run("GIVEN_cipherText_WHEN_decrypt_with_different_key_THEN_throw_err", func(t *testing.T) {
		wrongKey, _ := NewKey(b64StdEncoder)
		wrongAes, _ := NewAesCipher(wrongKey, b64StdEncoder)

		cipherText, _ := EncryptCBC(aes, utf8PlainText, utf8Encoder, b64StdEncoder)
		plainText, err := DecryptCBC(wrongAes, cipherText, b64StdEncoder, utf8Encoder)

		fmt.Print(err.Error())
		if err == nil {
			t.Errorf("Expected error, got nil")
		}
		if plainText != "" {
			t.Errorf("Failed, expect empty plainText, got: %s", plainText)
		}

	})
}

func Test_pkcs7Pad(t *testing.T) {
	t.Run("error-invalid-blockSize", func(t *testing.T) {
		output, err := pkcs7Pad(randomBytes(), -1)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrInvalidBlockSize {
			t.Errorf("Expected err message: %s, got: %s", ErrInvalidBlockSize, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})

	t.Run("error-invalid-PKCS7Data", func(t *testing.T) {
		utf8Encoder := &text_encoder.Utf8Encoder{}
		key, _ := NewKey(utf8Encoder)
		aes, _ := NewAesCipher(key, utf8Encoder)

		output, err := pkcs7Pad(nil, aes.BlockSize())

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrEmptyOrNotPaddedPKCS7Data {
			t.Errorf("Expected err message: %s, got: %s", ErrEmptyOrNotPaddedPKCS7Data, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})
}

func Test_pkcs7Unpad(t *testing.T) {
	t.Run("error-invalid-blockSize", func(t *testing.T) {
		output, err := pkcs7Unpad(randomBytes(), -1)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrInvalidBlockSize {
			t.Errorf("Expected err message: %s, got: %s", ErrInvalidBlockSize, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})

	t.Run("error-invalid-PKCS7Data", func(t *testing.T) {
		utf8Encoder := &text_encoder.Utf8Encoder{}
		key, _ := NewKey(utf8Encoder)
		aes, _ := NewAesCipher(key, utf8Encoder)

		output, err := pkcs7Unpad(nil, aes.BlockSize())

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrEmptyOrNotPaddedPKCS7Data {
			t.Errorf("Expected err message: %s, got: %s", ErrEmptyOrNotPaddedPKCS7Data, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})

	t.Run("error-input-not-muliple-of-blockSize", func(t *testing.T) {
		utf8Encoder := &text_encoder.Utf8Encoder{}
		key, _ := NewKey(utf8Encoder)
		aes, _ := NewAesCipher(key, utf8Encoder)

		output, err := pkcs7Unpad(randomBytesOfLength(10), aes.BlockSize())

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrInvalidPKCS7Padding {
			t.Errorf("Expected err message: %s, got: %s", ErrInvalidPKCS7Padding, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})

	t.Run("error-invalid-pkcs7-padding", func(t *testing.T) {
		output, err := pkcs7Unpad(randomBytesOfLength(16), 16)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrInvalidPKCS7Padding {
			t.Errorf("Expected err message: %s, got: %s", ErrInvalidPKCS7Padding, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})

	t.Run("error-invalid-pkcs7-padding2", func(t *testing.T) {
		byteArr := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
		output, err := pkcs7Unpad(byteArr, 5)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if err.Error() != ErrInvalidPKCS7Padding {
			t.Errorf("Expected err message: %s, got: %s", ErrInvalidPKCS7Padding, err.Error())
		}
		if output != nil {
			t.Errorf("Expected nil output, got something")
		}
	})
}

func Test_pkcs7PadThenpkcs7Unpad(t *testing.T) {
	for i := 0; i < 100; i++ {
		blockSize := 16
		multiple := rand.Intn(100-10) + 10
		byteArr := randomBytesOfLength(multiple * blockSize)

		padded, err := pkcs7Pad(byteArr, blockSize)
		if err != nil {
			t.Errorf("Expected no error in padding, got: %s", err.Error())
		}

		unpadded, err := pkcs7Unpad(padded, blockSize)
		if err != nil {
			t.Errorf("Expected no error in unpadding, got: %s", err.Error())
		}

		isSame := bytes.Compare(unpadded, byteArr)
		if isSame != 0 {
			t.Errorf("Cannot unpad own padded byteArray")
		}
	}
}

func randomBytes() []byte {
	num := rand.Intn(100-10) + 10
	byteArr := make([]byte, num)
	cryptoRand.Read(byteArr)

	return byteArr
}

func randomBytesOfLength(length int) []byte {
	byteArr := make([]byte, length)
	cryptoRand.Read(byteArr)

	return byteArr
}
