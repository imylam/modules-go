package hmac

import (
	"crypto"
	"crypto/hmac"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"strings"
	"testing"

	"github.com/imylam/modules-go/crypto_utils/sha"
	"github.com/imylam/modules-go/stringutils"
	"github.com/imylam/modules-go/text_encoder"
)

var testMsg = "golang is great"
var testKey = "Golang"
var testSha1Signature = "8a2ec61d4d9f5c7e087615e714475c1b6130f6e8"
var testSha256Signature = "c3755c8cc0293311a0200e28893d7ef9a6a60748ccfda709c45746e4b6a7e0ae"
var testSha512Signature = "3e62f4595cb9f047a00c9eca5fcc816675465ef2613be2b762fed1d94d9a348924ef3c72f0aa8f9d99f0018cd55252ba3f86dcbbde5fe43fba42e8e44eb94d97"
var testSha3256Signature = "0ce2cd6585cdf1f0a3c0c19bde2ec7f9b2ac54f061df3d551517c0c8fc1aa3a0"
var testSha3512Signature = "d7456c735110e6d16360b2021508937a93bfa891365f66e9757e4ffc3b54b9563b96c7a614266849612251bfbf5c5e3352696cbc70aa2fbbc3c218f4f2e8debd"

func Test_HmacSha1Sign(t *testing.T) {
	// Create test input and key randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)
	key := make([]byte, num)
	cryptoRand.Read(key)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		msgStr := base64.StdEncoding.EncodeToString(input)
		keyStr := base64.StdEncoding.EncodeToString(key)
		expected := base64.StdEncoding.EncodeToString(hmacSign(input, key, crypto.SHA1))

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, b64StdEncoder, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if signStr != expected {
			t.Errorf("Expect signature: %s, got: %s", expected, signStr)
		}

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signStr, b64StdEncoder, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if !isSignatureValid {
			t.Errorf("Cannot verify own signature")
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		keyStr := base64.StdEncoding.EncodeToString(key)
		msgStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(hmacSign(input, key, crypto.SHA1))

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, b64StdEncoder, b64StdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if signStr != expected {
			t.Errorf("Expect signature: %s, got: %s", expected, signStr)
		}

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signStr, b64StdEncoder, b64StdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if !isSignatureValid {
			t.Errorf("Cannot verify own signature")
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		keyStr := base64.StdEncoding.EncodeToString(key)
		msgStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(hmacSign(input, key, crypto.SHA1))

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, b64StdEncoder, b64StdEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if signStr != expected {
			t.Errorf("Expect signature: %s, got: %s", expected, signStr)
		}

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signStr, b64StdEncoder, b64StdEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if !isSignatureValid {
			t.Errorf("Cannot verify own signature")
		}
	})

	t.Run("b64StdIn-HexOut", func(t *testing.T) {
		msgStr := base64.StdEncoding.EncodeToString(input)
		keyStr := base64.StdEncoding.EncodeToString(key)
		expected := hex.EncodeToString(hmacSign(input, key, crypto.SHA1))

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, b64StdEncoder, b64StdEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if signStr != expected {
			t.Errorf("Expect signature: %s, got: %s", expected, signStr)
		}

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signStr, b64StdEncoder, b64StdEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if !isSignatureValid {
			t.Errorf("Cannot verify own signature")
		}
	})
}

func Test_HmacSha3512SignThenVerify(t *testing.T) {
	key := stringutils.RandomString(20)
	msg := stringutils.RandomString(50)

	// Create encoders
	keyEncoder := &text_encoder.Utf8Encoder{}
	msgEncoder := &text_encoder.Utf8Encoder{}
	signatureEncoder := &text_encoder.HexEncoder{}

	t.Run("success", func(t *testing.T) {
		signature, err := Sign(crypto.SHA3_512, key, msg, keyEncoder, msgEncoder, signatureEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		isValid, err := Verify(crypto.SHA3_512, key, msg, signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isValid {
			t.Errorf("Failure to verify own signed signature")
		}
		if err != nil {
			t.Errorf("Expected error to be nil, got: %s", err.Error())
		}
	})

	t.Run("GIVEN_different-keys-used_WHEN_sign-and-verify_THEN_fail", func(t *testing.T) {
		wrongKey := stringutils.RandomString(50)
		signature, err := Sign(crypto.SHA3_512, key, msg, keyEncoder, msgEncoder, signatureEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		isValid, err := Verify(crypto.SHA3_512, wrongKey, msg, signature, keyEncoder, msgEncoder, signatureEncoder)
		if isValid {
			t.Errorf("Expected failure to verify signature")
		}
		if err != nil {
			t.Errorf("Expected error to be nil, got: %s", err.Error())
		}
	})

	t.Run("GIVEN_invalid-signature_WHEN_verify_THEN_fail", func(t *testing.T) {
		randomSignature, _ := sha.Hash(stringutils.RandomString(50), crypto.SHA3_512, keyEncoder, signatureEncoder)
		_, _ = Sign(crypto.SHA3_512, key, msg, keyEncoder, msgEncoder, signatureEncoder)
		isValid, err := Verify(crypto.SHA3_512, key, msg, randomSignature, keyEncoder, msgEncoder, signatureEncoder)

		if isValid {
			t.Errorf("Expected failure to verify signature")
		}
		if err != nil {
			t.Errorf("Expected error to be nil, got: %s", err.Error())
		}
	})
}

func Test_HexHmacSign(t *testing.T) {
	// Create encoders
	keyEncoder := &text_encoder.Utf8Encoder{}
	msgEncoder := &text_encoder.Utf8Encoder{}
	signatureEncoder := &text_encoder.HexEncoder{}

	t.Run("sha1", func(t *testing.T) {
		signature, _ := Sign(crypto.SHA1, testKey, testMsg, keyEncoder, msgEncoder, signatureEncoder)

		if signature != testSha1Signature {
			t.Errorf("Expect signature: %s, got: %s", testSha1Signature, signature)
		}
	})

	t.Run("sha256", func(t *testing.T) {
		signature, _ := Sign(crypto.SHA256, testKey, testMsg, keyEncoder, msgEncoder, signatureEncoder)

		if signature != testSha256Signature {
			t.Errorf("Expect signature: %s, got: %s", testSha256Signature, signature)
		}
	})

	t.Run("sha512", func(t *testing.T) {
		signature, _ := Sign(crypto.SHA512, testKey, testMsg, keyEncoder, msgEncoder, signatureEncoder)

		if signature != testSha512Signature {
			t.Errorf("Expect signature: %s, got: %s", testSha512Signature, signature)
		}
	})

	t.Run("sha3-256", func(t *testing.T) {
		signature, _ := Sign(crypto.SHA3_256, testKey, testMsg, keyEncoder, msgEncoder, signatureEncoder)

		if signature != testSha3256Signature {
			t.Errorf("Expect signature: %s, got: %s", testSha3256Signature, signature)
		}
	})

	t.Run("sha3-512", func(t *testing.T) {
		signature, _ := Sign(crypto.SHA3_512, testKey, testMsg, keyEncoder, msgEncoder, signatureEncoder)

		if signature != testSha3512Signature {
			t.Errorf("Expect signature: %s, got: %s", testSha3512Signature, signature)
		}
	})
}

func Test_HexHmacVerify(t *testing.T) {
	// Create encoders
	keyEncoder := &text_encoder.Utf8Encoder{}
	msgEncoder := &text_encoder.Utf8Encoder{}
	signatureEncoder := &text_encoder.HexEncoder{}

	t.Run("sha1", func(t *testing.T) {
		isSignatureValid, _ := Verify(crypto.SHA256, testKey, testMsg, testSha256Signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isSignatureValid {
			t.Errorf("Failed, cannot verify signature")
		}
	})

	t.Run("sha256", func(t *testing.T) {
		isSignatureValid, _ := Verify(crypto.SHA256, testKey, testMsg, testSha256Signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isSignatureValid {
			t.Errorf("Failed, cannot verify signature")
		}
	})

	t.Run("sha512", func(t *testing.T) {
		isSignatureValid, _ := Verify(crypto.SHA512, testKey, testMsg, testSha512Signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isSignatureValid {
			t.Errorf("Failed, cannot verify signature")
		}
	})

	t.Run("sha3-256", func(t *testing.T) {
		isSignatureValid, _ := Verify(crypto.SHA3_256, testKey, testMsg, testSha3256Signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isSignatureValid {
			t.Errorf("Failed, cannot verify signature")
		}
	})

	t.Run("sha3-512", func(t *testing.T) {
		isSignatureValid, _ := Verify(crypto.SHA3_512, testKey, testMsg, testSha3512Signature, keyEncoder, msgEncoder, signatureEncoder)

		if !isSignatureValid {
			t.Errorf("Failed, cannot verify signature")
		}
	})
}

func Test_SignThrowError(t *testing.T) {
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)
	key := make([]byte, num)
	cryptoRand.Read(key)

	// Create encoders
	utf8Encoder := &text_encoder.Utf8Encoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("GIVEN_invalid-msg-encoding_WHEN_sign_THEN_throw-err", func(t *testing.T) {
		msgStr := base64.StdEncoding.EncodeToString(input)
		keyStr := hex.EncodeToString(key)

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, hexEncoder, hexEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Epected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeMsg) {
			t.Errorf("Expected error message contain: %s, got %s", ErrDecodeMsg, err.Error())
		}
		if signStr != "" {
			t.Errorf("Expected empty string, got: %s", signStr)
		}
	})

	t.Run("GIVEN_invalid-key-encoding_WHEN_sign_THEN_throw-err", func(t *testing.T) {
		msgStr := "aa"
		keyStr := base64.StdEncoding.EncodeToString(key)

		signStr, err := Sign(crypto.SHA1, keyStr, msgStr, hexEncoder, utf8Encoder, hexEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeKey) {
			t.Errorf("Expected error message contain: %s, got %s", ErrDecodeKey, err.Error())
		}
		if signStr != "" {
			t.Errorf("Expected empty string, got: %s", signStr)
		}
	})
}

func Test_VerifyThrowError(t *testing.T) {
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)
	key := make([]byte, num)
	cryptoRand.Read(key)
	signature := make([]byte, num)
	cryptoRand.Read(signature)

	// Create encoders
	utf8Encoder := &text_encoder.Utf8Encoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("GIVEN_invalid-msg-encoding_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		keyStr := hex.EncodeToString(key)
		msgStr := base64.StdEncoding.EncodeToString(input)
		signatureStr := hex.EncodeToString(signature)

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signatureStr, hexEncoder, hexEncoder, hexEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeMsg) {
			t.Errorf("Expected error message contain: %s, got %s", ErrDecodeMsg, err.Error())
		}
		if isSignatureValid {
			t.Errorf("Expected isSignatureValid to be false")
		}
	})

	t.Run("GIVEN_invalid-signature-encoding_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		keyStr := hex.EncodeToString(key)
		msgStr := "aa"
		signatureStr := base64.StdEncoding.EncodeToString(signature)

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signatureStr, hexEncoder, hexEncoder, hexEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeSignature) {
			t.Errorf("Expected error message contain: %s, got %s", ErrDecodeSignature, err.Error())
		}
		if isSignatureValid {
			t.Errorf("Expected isSignatureValid to be false")
		}
	})

	t.Run("GIVEN_invalid-key-encoding_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		msgStr := "aa"
		signatureStr := "aa"
		keyStr := base64.StdEncoding.EncodeToString(key)

		isSignatureValid, err := Verify(crypto.SHA1, keyStr, msgStr, signatureStr, hexEncoder, utf8Encoder, hexEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeKey) {
			t.Errorf("Expected error message contain: %s, got %s", ErrDecodeKey, err.Error())
		}
		if isSignatureValid {
			t.Errorf("Expected isSignatureValid to be false")
		}
	})
}

func hmacSign(input, key []byte, hasher crypto.Hash) []byte {
	hash := hmac.New(hasher.HashFunc().New, key)
	hash.Reset()
	hash.Write(input)

	return hash.Sum(nil)
}
