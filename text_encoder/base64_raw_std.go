package text_encoder

import "encoding/base64"

type Base64RawStdEncoder struct{}

func (e *Base64RawStdEncoder) Decode(input string) (output []byte, err error) {
	return base64.RawStdEncoding.DecodeString(input)
}

func (e *Base64RawStdEncoder) Encode(input []byte) string {
	return base64.RawStdEncoding.EncodeToString(input)
}
