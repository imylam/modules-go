package sha

import (
	"crypto"
	cryptoRand "crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"testing"

	"github.com/imylam/modules-go/text_encoder"
	"golang.org/x/crypto/sha3"
)

func Test_Sha1Sign(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64StdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64StdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-hexOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64StdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawStdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawStdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawStdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawUrlEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawUrlEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, b64RawUrlEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("hexIn-b64StdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha1Hash(input))

		hash, _ := Hash(inputStr, crypto.SHA1, hexEncoder, b64StdEncoder)

		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, hexEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, hexEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := hex.EncodeToString(sha1Hash(input))

		hash, err := Hash(inputStr, crypto.SHA1, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})
}

func Test_Sha256Sign(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64StdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64StdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-hexOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64StdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawStdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawStdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawStdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawUrlEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawUrlEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, b64RawUrlEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("hexIn-b64StdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, hexEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, hexEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, hexEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := hex.EncodeToString(sha256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA256, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})
}

func Test_Sha512Sign(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64StdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64StdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-hexOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64StdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawStdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawStdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawStdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawUrlEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawUrlEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, b64RawUrlEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("hexIn-b64StdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, hexEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, hexEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, hexEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := hex.EncodeToString(sha512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA512, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})
}

func Test_Sha3256Sign(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64StdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64StdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-hexOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64StdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawStdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawStdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawStdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawUrlEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawUrlEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, b64RawUrlEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("hexIn-b64StdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, hexEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, hexEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, hexEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := hex.EncodeToString(sha3256Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_256, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})
}

func Test_Sha3512Sign(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	// Create encoders
	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	b64RawStdEncoder := &text_encoder.Base64RawStdEncoder{}
	b64RawUrlEncoder := &text_encoder.Base64RawUrlEncoder{}
	hexEncoder := &text_encoder.HexEncoder{}

	t.Run("b64StdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64StdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64StdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64StdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64StdIn-hexOut", func(t *testing.T) {
		inputStr := base64.StdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64StdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawStdEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawStdEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawStdEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawStdIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawStdEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawStdEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64StdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawUrlEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawUrlEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawUrlEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := base64.RawURLEncoding.EncodeToString(input)
		expected := hex.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, b64RawUrlEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("hexIn-b64StdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.StdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, hexEncoder, b64StdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawStdOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawStdEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, hexEncoder, b64RawStdEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-b64RawUrlOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := base64.RawURLEncoding.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, hexEncoder, b64RawUrlEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})

	t.Run("b64RawUrlIn-hexOut", func(t *testing.T) {
		inputStr := hex.EncodeToString(input)
		expected := hex.EncodeToString(sha3512Hash(input))

		hash, err := Hash(inputStr, crypto.SHA3_512, hexEncoder, hexEncoder)

		if err != nil {
			t.Errorf("Failed, expect no error, got: %s", err.Error())
		}
		if hash != expected {
			t.Errorf("Failed, expect: %s, got: %s", expected, hash)
		}
	})
}

func Test_ShaFailing(t *testing.T) {
	// Create test input randomly
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	b64StdEncoder := &text_encoder.Base64StdEncoder{}
	hash, err := Hash("abcdefg", crypto.SHA1, b64StdEncoder, b64StdEncoder)

	if err == nil {
		t.Errorf("Failed, expect error, got nil")
	}
	if hash != "" {
		t.Errorf("Failed, expect hash: %s, got: %s", "", hash)
	}
}

func sha1Hash(input []byte) []byte {
	hasher := sha1.New()
	hasher.Write(input)
	return hasher.Sum(nil)
}

func sha256Hash(input []byte) []byte {
	hasher := sha256.New()
	hasher.Write(input)
	return hasher.Sum(nil)
}

func sha512Hash(input []byte) []byte {
	hasher := sha512.New()
	hasher.Write(input)
	return hasher.Sum(nil)
}

func sha3256Hash(input []byte) []byte {
	hasher := sha3.New256()
	hasher.Write(input)
	return hasher.Sum(nil)
}

func sha3512Hash(input []byte) []byte {
	hasher := sha3.New512()
	hasher.Write(input)
	return hasher.Sum(nil)
}
