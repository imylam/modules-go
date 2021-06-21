package bcrypt

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/imylam/modules-go/text_encoder"
)

var (
	password string = "password!"
)

func Test_BcryptSignThenVerify(t *testing.T) {
	// Create encoders
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("GIVEN_hash_WHEN_verify_THEN_verify-succeessfully", func(t *testing.T) {
		hash, err := Hash(password, utf8Encoder, utf8Encoder)
		isPwValid, err := Verify(password, hash, utf8Encoder, utf8Encoder)

		if err != nil {
			t.Errorf("Failed, expected error to be nil, got error: %s", err.Error())
		}
		if !isPwValid {
			t.Errorf("Failed, cannot verify own hash")
		}
	})

	t.Run("GIVEN_hash-of-another-pw_WHEN_verify_THEN_failed-to-verify", func(t *testing.T) {
		expectedErrMsg := "hashedPassword is not the hash of the given password"
		password2 := "imypassword@"

		hash, err := Hash(password, utf8Encoder, utf8Encoder)
		if err != nil {
			t.Errorf("Expected error to be nil, got: %s", err.Error())
		}

		isPwValid, err := Verify(password2, hash, utf8Encoder, utf8Encoder)

		if err == nil {
			t.Errorf("Failed, expect err, got nil")
		}
		if isPwValid {
			t.Errorf("Failed, verification should fail")
		}
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Failed, expected error message contain: %s, got %s", expectedErrMsg, err.Error())
		}
	})
}

func Test_BcryptHashErrorThrowing(t *testing.T) {
	// Create encoders
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("GIVEN_invalid-pw-encoding_WHEN_hash_THEN_throw-err", func(t *testing.T) {
		pwStr := base64.StdEncoding.EncodeToString([]byte(password))

		hash, err := Hash(pwStr, hexEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Failed, expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodePw) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrDecodePw, err.Error())
		}
		if hash != "" {
			t.Errorf("Failed, expected hash to be empty string, got: %s", hash)
		}
	})
}

func Test_BcryptVerifyErrorThrowing(t *testing.T) {
	// Create encoders
	hexEncoder := &text_encoder.HexEncoder{}
	utf8Encoder := &text_encoder.Utf8Encoder{}

	t.Run("GIVEN_invalid-pw-encoding_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		pwStr := base64.StdEncoding.EncodeToString([]byte(password))

		isPwValid, err := Verify(pwStr, "hello", hexEncoder, utf8Encoder)

		if err == nil {
			t.Errorf("Failed, expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodePw) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrDecodePw, err.Error())
		}
		if isPwValid {
			t.Errorf("Failed, expected isPwValid to be false")
		}
	})

	t.Run("GIVEN_invalid-signature-encoding_WHEN_verify_THEN_throw-err", func(t *testing.T) {
		hashStr := base64.StdEncoding.EncodeToString([]byte(password))

		isPwValid, err := Verify(password, hashStr, utf8Encoder, hexEncoder)

		if err == nil {
			t.Errorf("Failed, expected error thrown, got nil")
		}
		if !strings.Contains(err.Error(), ErrDecodeHash) {
			t.Errorf("Failed, expected error message contain: %s, got %s", ErrDecodeHash, err.Error())
		}
		if isPwValid {
			t.Errorf("Failed, expected isPwValid to be false")
		}
	})
}
