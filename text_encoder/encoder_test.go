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

	b64Encoder := &Base64StdEncoder{}
	b64RawStdEncoder := &Base64RawStdEncoder{}
	b64RawUrlEncoder := &Base64RawUrlEncoder{}
	hexEncoder := &HexEncoder{}
	utf8Encoder := &Utf8Encoder{}

	num := rand.Intn(100-10) + 10
	randomInput := make([]byte, num)
	cryptoRand.Read(randomInput)

	b64Input := base64.StdEncoding.EncodeToString(randomInput)
	b64RawStdInput := base64.RawStdEncoding.EncodeToString(randomInput)
	b64RawUrlInput := base64.RawURLEncoding.EncodeToString(randomInput)
	hexInput := hex.EncodeToString(randomInput)
	utf8Input := string(randomInput)

	type args struct {
		s string
	}

	testCases := []struct {
		name    string
		encoder Encoder
		args    args
		want    int
	}{
		{name: "test-b64std", encoder: b64Encoder, args: args{s: b64Input}, want: 0},
		{name: "test-b64RawStd", encoder: b64RawStdEncoder, args: args{s: b64RawStdInput}, want: 0},
		{name: "test-b64RawUrl", encoder: b64RawUrlEncoder, args: args{s: b64RawUrlInput}, want: 0},
		{name: "test-hex", encoder: hexEncoder, args: args{s: hexInput}, want: 0},
		{name: "test-utf8", encoder: utf8Encoder, args: args{s: utf8Input}, want: 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, _ := tc.encoder.Decode(tc.args.s)

			isSame := bytes.Compare(result, randomInput)

			if isSame != tc.want {
				t.Fail()
			}
		})
	}
}

func Test_Encoding(t *testing.T) {
	b64Encoder := &Base64StdEncoder{}
	b64RawStdEncoder := &Base64RawStdEncoder{}
	b64RawUrlEncoder := &Base64RawUrlEncoder{}
	hexEncoder := &HexEncoder{}
	utf8Encoder := &Utf8Encoder{}

	num := rand.Intn(100-10) + 10
	randomInput := make([]byte, num)
	cryptoRand.Read(randomInput)

	b64Input := base64.StdEncoding.EncodeToString(randomInput)
	b64RawStdInput := base64.RawStdEncoding.EncodeToString(randomInput)
	b64RawUrlInput := base64.RawURLEncoding.EncodeToString(randomInput)
	hexInput := hex.EncodeToString(randomInput)
	utf8Input := string(randomInput)

	testCases := []struct {
		name    string
		encoder Encoder
		want    string
	}{
		{name: "test-b64std", encoder: b64Encoder, want: b64Input},
		{name: "test-b64RawStd", encoder: b64RawStdEncoder, want: b64RawStdInput},
		{name: "test-b64RawUrl", encoder: b64RawUrlEncoder, want: b64RawUrlInput},
		{name: "test-hex", encoder: hexEncoder, want: hexInput},
		{name: "test-utf8", encoder: utf8Encoder, want: utf8Input},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.encoder.Encode(randomInput)

			if result != tc.want {
				t.Errorf("Failed, expected: %s, got: %s", tc.want, result)
			}
		})
	}
}

func RandomInput() {

}
