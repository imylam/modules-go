package sha

import (
	"crypto"

	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"

	_ "golang.org/x/crypto/sha3"

	"github.com/imylam/modules-go/text_encoder"
)

func Hash(input string, hasher crypto.Hash, inEncoder, outEncoder text_encoder.Encoder) (hash string, err error) {
	hasherFunc := hasher.HashFunc().New()

	inputByte, err := inEncoder.Decode(input)
	if err != nil {
		return "", err
	}

	hasherFunc.Write(inputByte)
	hash = outEncoder.Encode(hasherFunc.Sum(nil))

	return
}
