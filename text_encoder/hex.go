package text_encoder

import (
	"encoding/hex"
)

type HexEncoder struct{}

func (e *HexEncoder) Decode(input string) (output []byte, err error) {
	return hex.DecodeString(input)
}

func (e *HexEncoder) Encode(input []byte) string {
	return hex.EncodeToString(input)
}
