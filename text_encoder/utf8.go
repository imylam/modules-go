package text_encoder

type Utf8Encoder struct{}

func (e *Utf8Encoder) Decode(input string) (output []byte, err error) {
	return []byte(input), nil
}

func (e *Utf8Encoder) Encode(input []byte) string {
	return string(input)
}
