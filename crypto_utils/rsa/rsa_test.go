package rsa

import (
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/rsa"
	"math/rand"
	"strings"
	"testing"

	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser"
	"github.com/imylam/modules-go/crypto_utils/rsa/key_parser/x509"
	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/text_encoder"
)

const (
	privatePemLength int = 1700
)

var (
	testPlainString     string = "imylam/crypto"
	testCipherString    string = "V7qj3oJxTxdV5HDCQNJdATcQHGA6gjtOSMOC1dBuzBctS3ZjbxSIckonb4Jeo8iuB/57PZFE3Kmlo8vH8/eOsHBC0gplCn2cwo4fxrRx+3hUN8rDUWGtZ2U7mhcNYbxj1vksFgJf1XAGcOrAbDYgjzhsLSDyzyfGg6zXSot+GHGpooMSjX9w0OGp3/bJ5/i0eAFHH9Q5Zi8TZHoi1mzF4HdgVUsruaNUmA5CX09EEPQcFSaT3w2KSjSvQtkaNzAHeKvdOVvzu+/fZ8x0Lk1X4OUaexgZCrAJcfbMewDbhypSxzDO0fMoc/1LAhB3RpbzeJ/r+6hld56s2GJ3wypnKg=="
	testSignatureString string = "pS0e99AZZZ5yNjRKU8LXRFtTI2DymgpBWWhVrqqEPPJSNDfv/g2FAfcguI34HAO9rzLhyTWV1PAFHceUE0LM316YpOm+klYaiTUyqACNX2WTjfBZOb93a7I3QRnbTN91DRPCYgDx06mcoKEGBw5T3HPca1k/1oargixb5Igb3p89791eTHC1LrgZ+TzNSk/N95M8QZXbKrglXzfXqy3g2/JS7YnRY9nB1dFGxUOPT5YwNLzkRhs8j04XaE6vVKHYlHpXYialPmngjVeOsBehXBpMgvvYn8fsCfsDC5MN/rUHthx7f9RgsmiE0ZrEMb49RgrPh0Ybm6FNw7ceNMqGiQ=="

	pkcs1PrivateKeyPem = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxD8FDhP4c9GF8Or8vea+NZqDx/UqqBq+l9Z9Qr0JWVGpMXiG
EwfwQwDAyDibEeT+3naS2Ts1hb1Yt+TywgaVmi8/r2rNFDGmjpUy+/I/7dzZakXE
LLve7sPBBhsDigflRTq0M+QTWt9zRz9rnGhW7diYywbhalEB3RrlIwJsN2oF/AU4
CVGlQwzO/FsOE/od3HEulAcAfFbdJsxRbpwPDFLz68E455ljJfPDXntQxr7QKA+3
+cCP518B6xykTqWMvagkCGq7S2wTKZXFIX/RC3FAjLS3LCdT99+62KlHP4Nhd2M/
BYb4H0rAk1RU7KOw+O88LpOauLUlPUim5jDJWQIDAQABAoIBAQCjx9CJMkONLVTy
frsWJcei5uSKceL6zu83u0to8mkmARAKeIK0yVBMKwm5T/yjD5FhymW+JDsD9cVg
HBQ5t9MNDdfBp4mmC9XsczpMqJ2P/1v35GfXyadBb1/dn5fxj6tZfqe8EuHQWmJU
GOrPawj5kWXbM0/XMeozRGntMO1txHhlXuN+3MaPZBZZJqBD2qKkOQkRU+TjzMUa
DGuHfseSc3prbeIhx9sXZGLm9BYdpej+CGYMJKipscEGiRVPAfmXo8J9tUpQsYiE
cgEFyW2Um1RZ35X4B9pOE8Yolf0U4xqzzU6HBKPMR41CjwLlXsmVK96ap9AYd7fV
EQJj4J5tAoGBAO/MLUV8aX9ImhWteN1ipcvr2y+dTyJcF6MslpA3A2+Zid8+aptW
OvTIpTALe8QnylVBVIUtEDRMrW8g4WDbbnjQY30V2VdDDxTCCJKDh/Ftiex8pSSP
/3OvTTqibttGvkAQI9sJUJTbHpe7PMD+fVRU5pDCMgYUNcDj7ZLyeILHAoGBANGB
hryZdWr91ECvks6VHHEi0FsTBXqN7nI4GQmEa6SWJEkeLKgoHlZBCgYDfGa+LH99
CzAVFDLRFXOw/TIygrUODHsX/oagVv8/QTK/xMshTe88BAWe/QF98ZMiJyFbFUWd
5ai9gJfhU/qNriNZMJDKhP5/8sonRsB4v6aA9DLfAoGANicV0itWZ7gtk9epA9XT
O0n4JbiQtmG1tNPM7KR/0iQKTq/5wzql9cGaDE+Lk7CosLggLjMPBcCLKh1yyDzF
peLplMXqXxp1vWpUJUIu4Qarrww2/xrFxYpBFoy4HCzNqgn7Duv7lqIlNn7CKZNP
GkxSBT7VrSnDOdw/OoAnVuECgYApiRVuVLpLsPEgte5UGIngADfwpm/CoVrxuB92
nJM+uSmOeXX/DJ0fGpvjH1PNhsyJpf/O048CmCM5oZBBIHR7csKUsOgcRrOYvTCu
4AgjAYJS+MIPXzrnzdFUC0RYv5cTCz/Z2WAiPGEK3oX0qh0Px6bgUfuPioPjas0M
NKq1XwKBgGoTJn4BsEGMPIOYf4sHnj4v0IVyi1n27fifdFJSEjxxO6M5gWVd3d5t
eog14W6s9kg77JWss8xf6fMynkXkvaeyzYS2e25e9T1TcFL8Bxe20nqxCm7PX/5/
KXrbNz71H2RMKAE6alsPmLko52WATQnQKrSb+awdEDN4hRVUlIZK
-----END RSA PRIVATE KEY-----`
	pkcs1PublicKeyPem = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxD8FDhP4c9GF8Or8vea+NZqDx/UqqBq+l9Z9Qr0JWVGpMXiGEwfw
QwDAyDibEeT+3naS2Ts1hb1Yt+TywgaVmi8/r2rNFDGmjpUy+/I/7dzZakXELLve
7sPBBhsDigflRTq0M+QTWt9zRz9rnGhW7diYywbhalEB3RrlIwJsN2oF/AU4CVGl
QwzO/FsOE/od3HEulAcAfFbdJsxRbpwPDFLz68E455ljJfPDXntQxr7QKA+3+cCP
518B6xykTqWMvagkCGq7S2wTKZXFIX/RC3FAjLS3LCdT99+62KlHP4Nhd2M/BYb4
H0rAk1RU7KOw+O88LpOauLUlPUim5jDJWQIDAQAB
-----END RSA PUBLIC KEY-----`
)

func TestGenKey(t *testing.T) {
	keyParser := &x509.Pkcs1Parser{}
	var privateKeyPem, publicKeyPem, privateKey, publicKey interface{}
	privateKeyPem, publicKeyPem, err := GenerateKeyPair(keyParser, keyParser)
	if err != nil {
		t.Errorf("Expect error to be nil, got: %s", err.Error())
	}

	privateKeyPem, ok := privateKeyPem.(string)
	if !ok {
		t.Errorf("PrivateKeyPem generated is not a string")
	}

	publicKeyPem, ok = publicKeyPem.(string)
	if !ok {
		t.Errorf("PublicKeyPem generated is not a string")
	}

	privateKey, _ = keyParser.ParsePrivateKeyFromPemStr(privateKeyPem.(string))
	publicKey, _ = keyParser.ParsePublicKeyFromPemStr(publicKeyPem.(string))

	privateKey, ok = privateKey.(*rsa.PrivateKey)
	if !ok {
		t.Errorf("PrivateKey generated is not of type *rsa.PrivateKey")
	}

	publicKey, ok = publicKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("PublicKey generated is not of type *rsa.PublicKey")
	}
}

func TestDecrypt(t *testing.T) {
	keyParser := &x509.Pkcs1Parser{}
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("success", func(t *testing.T) {
		plainText, err := Decrypt(crypto.SHA256, pkcs1PrivateKeyPem, testCipherString, keyParser, b64StdEncoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		if plainText != testPlainString {
			t.Errorf("Decrypting ciperText doesn't give original plainText.")
		}
	})

	t.Run("GIVEN_invalid-cipherTextEncoder_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		plainText, err := Decrypt(crypto.SHA256, pkcs1PrivateKeyPem, "cipherText", keyParser, b64StdEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeCipherText) {
			t.Errorf("Expected error message contain: %s, got: %s", ErrDecodeCipherText, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected plainText to be empty, got: %s", plainText)
		}
	})

	t.Run("GIVEN_invalid-private-key_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		plainText, err := Decrypt(crypto.SHA256, "privateKey", "cipherText", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), key_parser.ERR_PARSE_PRIVATE_KEY) {
			t.Errorf("Expected error message contain: %s, got: %s", ErrDecodeCipherText, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected plainText to be empty, got: %s", plainText)
		}
	})

	t.Run("GIVEN_invalid-cipherText_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		expectedErrMsg := "crypto/rsa: decryption error"
		plainText, err := Decrypt(crypto.SHA256, pkcs1PrivateKeyPem, "golang", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Expected error message contain: %s, got: %s", expectedErrMsg, err.Error())
		}
		if plainText != "" {
			t.Errorf("Expected plainText to be empty, got: %s", plainText)
		}
	})
}

func TestEncrypt(t *testing.T) {
	keyParser := &x509.Pkcs1Parser{}
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("success", func(t *testing.T) {
		var cipherText interface{}
		cipherText, err := Encrypt(crypto.SHA256, pkcs1PublicKeyPem, testPlainString, keyParser, utf8Encoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		cipherText, ok := cipherText.(string)
		if !ok {
			t.Errorf("Encrypted cipherText should be a string")
		}

		plainText, err := Decrypt(crypto.SHA256, pkcs1PrivateKeyPem, testCipherString, keyParser, b64StdEncoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if plainText != testPlainString {
			t.Errorf("Decrypting ciperText doesn't give original plainText.")
		}
	})

	t.Run("GIVEN_invalid-plainTextEncoder_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		plainText := randomString(utf8Encoder)
		cipherText, err := Encrypt(crypto.SHA256, plainText, pkcs1PublicKeyPem, keyParser, b64StdEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if cipherText != "" {
			t.Errorf("Expected empty string, got %s", cipherText)
		}
	})

	t.Run("GIVEN_invalid-public-key_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		plainText := randomString(utf8Encoder)
		cipherText, err := Encrypt(crypto.SHA256, plainText, "publicKey", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if cipherText != "" {
			t.Errorf("Expected empty string, got %s", cipherText)
		}
	})

	t.Run("GIVEN_input-too-long_WHEN_decrypt_THEN_throw-err", func(t *testing.T) {
		plainText := randomStringOfLength(500, utf8Encoder)
		cipherText, err := Encrypt(crypto.SHA256, plainText, "publicKey", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if cipherText != "" {
			t.Errorf("Expected empty string, got %s", cipherText)
		}
	})

}
func TestEncryptThenDecrypt(t *testing.T) {
	keyParser := &x509.Pkcs1Parser{}
	privateKeyPem, publicKeyPem, _ := GenerateKeyPair(keyParser, keyParser)
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("b64Std", func(t *testing.T) {
		plainText := randomString(b64StdEncoder)
		cipherText, err := Encrypt(crypto.SHA256, publicKeyPem, plainText, keyParser, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		decryptedText, err := Decrypt(crypto.SHA256, privateKeyPem, cipherText, keyParser, b64StdEncoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if decryptedText != plainText {
			t.Errorf("Decrypting cipherText doesn't give back plainText.")
		}
	})

	t.Run("b64RawStd", func(t *testing.T) {
		plainText := randomString(b64RawStdEncoder)
		cipherText, err := Encrypt(crypto.SHA256, publicKeyPem, plainText, keyParser, b64RawStdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		decryptedText, err := Decrypt(crypto.SHA256, privateKeyPem, cipherText, keyParser, b64RawStdEncoder, b64RawStdEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if decryptedText != plainText {
			t.Errorf("Decrypting cipherText doesn't give back plainText.")
		}
	})

	t.Run("b64RawUrl", func(t *testing.T) {
		plainText := randomString(b64RawUrlEncoder)
		cipherText, err := Encrypt(crypto.SHA256, publicKeyPem, plainText, keyParser, b64RawUrlEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		decryptedText, err := Decrypt(crypto.SHA256, privateKeyPem, cipherText, keyParser, b64RawUrlEncoder, b64RawUrlEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if decryptedText != plainText {
			t.Errorf("Decrypting cipherText doesn't give back plainText.")
		}
	})

	t.Run("hex", func(t *testing.T) {
		plainText := randomString(hexEncoder)
		cipherText, err := Encrypt(crypto.SHA256, publicKeyPem, plainText, keyParser, hexEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		decryptedText, err := Decrypt(crypto.SHA256, privateKeyPem, cipherText, keyParser, hexEncoder, hexEncoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if decryptedText != plainText {
			t.Errorf("Decrypting cipherText doesn't give back plainText.")
		}
	})

	t.Run("utf8", func(t *testing.T) {
		plainText := randomString(utf8Encoder)
		cipherText, err := Encrypt(crypto.SHA256, publicKeyPem, plainText, keyParser, utf8Encoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}

		decryptedText, err := Decrypt(crypto.SHA256, privateKeyPem, cipherText, keyParser, utf8Encoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expect error to be nil, got: %s", err.Error())
		}
		if decryptedText != plainText {
			t.Errorf("Decrypting cipherText doesn't give back plainText.")
		}
	})
}

func TestSign(t *testing.T) {
	var signatureInterface interface{}

	hasher := crypto.SHA512
	keyParser := &x509.Pkcs1Parser{}
	signScheme := sign_scheme.NewRsaSignPss()
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("success", func(t *testing.T) {
		signature, _ := Sign(hasher, signScheme, pkcs1PrivateKeyPem, testPlainString, keyParser, utf8Encoder, b64StdEncoder)
		signatureInterface = signature
		_, ok := signatureInterface.(string)
		if !ok {
			t.Errorf("Signature should be a string")
		}

		err := Verify(hasher, signScheme, string(pkcs1PublicKeyPem), testPlainString, signature, keyParser, utf8Encoder, b64StdEncoder)
		if err != nil {
			t.Errorf("Fail to verify the signature. Error: %s", err.Error())
		}
	})

	t.Run("GIVEN_invalid-message-encoder_WHEN_sign_THEN_throw-err", func(t *testing.T) {
		message := randomString(utf8Encoder)
		signature, err := Sign(crypto.SHA256, signScheme, pkcs1PrivateKeyPem, message, keyParser, b64StdEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeMsg) {
			t.Errorf("Expected error message contain: %s, got: %s", ErrDecodeMsg, err.Error())
		}
		if signature != "" {
			t.Errorf("Expect signature to be empty, got: %s", signature)
		}
	})

	t.Run("GIVEN_invalid-privateKey_WHEN_sign_THEN_throw-err", func(t *testing.T) {
		signature, err := Sign(crypto.SHA256, signScheme, "privateKey", "message", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), key_parser.ERR_PARSE_PRIVATE_KEY) {
			t.Errorf("Expected error message contain: %s, got: %s", key_parser.ERR_PARSE_PRIVATE_KEY, err.Error())
		}
		if signature != "" {
			t.Errorf("Expect signature to be empty, got: %s", signature)
		}
	})
}

func TestVerify(t *testing.T) {
	hasher := crypto.SHA512
	signScheme := sign_scheme.NewRsaSignPss()
	keyParser := &x509.Pkcs1Parser{}
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("success", func(t *testing.T) {
		err := Verify(hasher, signScheme, pkcs1PublicKeyPem, testPlainString, testSignatureString, keyParser, utf8Encoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed to verify, reason: %s", err.Error())
		}
	})

	t.Run("GIVEN_invalid-message-encoder_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		err := Verify(hasher, signScheme, pkcs1PublicKeyPem, "message", "signature", keyParser, b64StdEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeMsg) {
			t.Errorf("Expected error message contain: %s, got: %s", ErrDecodeMsg, err.Error())
		}
	})

	t.Run("GIVEN_invalid-signature-encoder_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		err := Verify(hasher, signScheme, pkcs1PublicKeyPem, "message", "signature", keyParser, utf8Encoder, b64StdEncoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeSignature) {
			t.Errorf("Expected error message contain: %s, got: %s", ErrDecodeSignature, err.Error())
		}
	})

	t.Run("GIVEN_invalid_signature_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		expectedErrMsg := "crypto/rsa: verification error"
		message := randomString(utf8Encoder)
		err := Verify(crypto.SHA256, signScheme, pkcs1PublicKeyPem, message, "toBeFailed", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Expected error message contain: %s, got: %s", expectedErrMsg, err.Error())
		}
	})

	t.Run("GIVEN_invalid-publicKey_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		err := Verify(crypto.SHA256, signScheme, "publicKey", "message", "signature", keyParser, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), key_parser.ERR_PARSE_PUBLIC_KEY) {
			t.Errorf("Expected error message contain: %s, got: %s", key_parser.ERR_PARSE_PUBLIC_KEY, err.Error())
		}
	})
}

func TestSignThenVerify(t *testing.T) {
	signScheme := sign_scheme.NewRsaSignPss()
	keyParser := &x509.Pkcs1Parser{}
	privateKeyPem, publicKeyPem, _ := GenerateKeyPair(keyParser, keyParser)
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("b64Std", func(t *testing.T) {
		message := randomString(b64StdEncoder)
		signature, _ := Sign(crypto.SHA256, signScheme, privateKeyPem, message, keyParser, b64StdEncoder, b64StdEncoder)
		err := Verify(crypto.SHA256, signScheme, publicKeyPem, message, signature, keyParser, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed to verify own signature")
		}
	})

	t.Run("b64RawStd", func(t *testing.T) {
		message := randomString(b64RawStdEncoder)
		signature, _ := Sign(crypto.SHA256, signScheme, privateKeyPem, message, keyParser, b64RawStdEncoder, b64RawStdEncoder)
		err := Verify(crypto.SHA256, signScheme, publicKeyPem, message, signature, keyParser, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed to verify own signature")
		}
	})

	t.Run("b64RawUrl", func(t *testing.T) {
		message := randomString(b64RawUrlEncoder)
		signature, _ := Sign(crypto.SHA256, signScheme, privateKeyPem, message, keyParser, b64RawUrlEncoder, b64RawUrlEncoder)
		err := Verify(crypto.SHA256, signScheme, publicKeyPem, message, signature, keyParser, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed to verify own signature")
		}
	})

	t.Run("hex", func(t *testing.T) {
		message := randomString(hexEncoder)
		signature, _ := Sign(crypto.SHA256, signScheme, privateKeyPem, message, keyParser, hexEncoder, hexEncoder)
		err := Verify(crypto.SHA256, signScheme, publicKeyPem, message, signature, keyParser, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed to verify own signature")
		}
	})

	t.Run("utf8", func(t *testing.T) {
		message := randomString(utf8Encoder)
		signature, _ := Sign(crypto.SHA256, signScheme, privateKeyPem, message, keyParser, utf8Encoder, utf8Encoder)
		err := Verify(crypto.SHA256, signScheme, publicKeyPem, message, signature, keyParser, utf8Encoder, utf8Encoder)

		if err != nil {
			t.Errorf("Failed to verify own signature")
		}
	})
}

func randomString(textEncoder text_encoder.Encoder) string {
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	return textEncoder.Encode(input)
}

func randomStringOfLength(length int, textEncoder text_encoder.Encoder) string {
	input := make([]byte, length)
	cryptoRand.Read(input)

	return textEncoder.Encode(input)
}
