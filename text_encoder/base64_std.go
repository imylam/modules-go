package text_encoder

import "encoding/base64"

type Base64StdEncoder struct{}

func (e *Base64StdEncoder) Decode(input string) (output []byte, err error) {
	return base64.StdEncoding.DecodeString(input)
}

func (e *Base64StdEncoder) Encode(input []byte) string {
	return base64.StdEncoding.EncodeToString(input)
}
