package text_encoder

import "encoding/base64"

type Base64RawUrlEncoder struct{}

func (e *Base64RawUrlEncoder) Decode(input string) (output []byte, err error) {
	return base64.RawURLEncoding.DecodeString(input)
}

func (e *Base64RawUrlEncoder) Encode(input []byte) string {
	return base64.RawURLEncoding.EncodeToString(input)
}
