package text_encoder

import (
	"bytes"
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"testing"
)

func Test_Decoding(t *testing.T) {
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	t.Run("test-b64std", func(t *testing.T) {
		encoder := &Base64StdEncoder{}
		encodedInput := base64.StdEncoding.EncodeToString(input)
		result, _ := encoder.Decode(encodedInput)

		isSame := bytes.Compare(result, input)

		if isSame != 0 {
			t.Errorf("Failed to decode string failed")
		}
	})

	t.Run("text-b64RawStd", func(t *testing.T) {
		encoder := &Base64RawStdEncoder{}
		encodedInput := base64.RawStdEncoding.EncodeToString(input)
		result, _ := encoder.Decode(encodedInput)

		isSame := bytes.Compare(result, input)

		if isSame != 0 {
			t.Errorf("Failed to decode string failed")
		}
	})

	t.Run("text-b64RawUrl", func(t *testing.T) {
		encoder := &Base64RawUrlEncoder{}
		encodedInput := base64.RawURLEncoding.EncodeToString(input)
		result, _ := encoder.Decode(encodedInput)

		isSame := bytes.Compare(result, input)

		if isSame != 0 {
			t.Errorf("Failed to decode string failed")
		}
	})

	t.Run("text-hex", func(t *testing.T) {
		encoder := &HexEncoder{}
		encodedInput := hex.EncodeToString(input)
		result, _ := encoder.Decode(encodedInput)

		isSame := bytes.Compare(result, input)

		if isSame != 0 {
			t.Errorf("Failed to decode string failed")
		}
	})

	t.Run("text-utf8", func(t *testing.T) {
		encoder := &Utf8Encoder{}
		encodedInput := string(input)
		result, _ := encoder.Decode(encodedInput)

		isSame := bytes.Compare(result, input)

		if isSame != 0 {
			t.Errorf("Failed to decode string failed")
		}
	})
}

func Test_Encoding(t *testing.T) {
	num := rand.Intn(100-10) + 10
	input := make([]byte, num)
	cryptoRand.Read(input)

	t.Run("test-b64std", func(t *testing.T) {
		encoder := &Base64StdEncoder{}
		result := encoder.Encode(input)

		expected := base64.StdEncoding.EncodeToString(input)

		if result != expected {
			t.Errorf("Failed, expected: %s, got: %s", expected, result)
		}
	})

	t.Run("text-b64RawStd", func(t *testing.T) {
		encoder := &Base64RawStdEncoder{}
		result := encoder.Encode(input)

		expected := base64.RawStdEncoding.EncodeToString(input)

		if result != expected {
			t.Errorf("Failed, expected: %s, got: %s", expected, result)
		}
	})

	t.Run("text-b64RawUrl", func(t *testing.T) {
		encoder := &Base64RawUrlEncoder{}
		result := encoder.Encode(input)

		expected := base64.RawURLEncoding.EncodeToString(input)

		if result != expected {
			t.Errorf("Failed, expected: %s, got: %s", expected, result)
		}
	})

	t.Run("text-hex", func(t *testing.T) {
		encoder := &HexEncoder{}
		result := encoder.Encode(input)

		expected := hex.EncodeToString(input)

		if result != expected {
			t.Errorf("Failed, expected: %s, got: %s", expected, result)
		}
	})

	t.Run("text-utf8", func(t *testing.T) {
		encoder := &Utf8Encoder{}
		result := encoder.Encode(input)

		expected := string(input)

		if result != expected {
			t.Errorf("Failed, expected: %s, got: %s", expected, result)
		}
	})
}
