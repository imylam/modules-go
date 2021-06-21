package bcrypt

import (
	"errors"

	"golang.org/x/crypto/bcrypt"

	"github.com/imylam/modules-go/text_encoder"
)

const (
	ErrDecodePw   = "failed to decode password: "
	ErrDecodeHash = "failed to decode hash: "
)

// Hash creates Bcrypt hash of a password
func Hash(pw string, pwEncoder, hashEncoder text_encoder.Encoder) (hash string, err error) {
	pwByte, err := pwEncoder.Decode(pw)
	if err != nil {
		return "", errors.New(ErrDecodePw + err.Error())
	}

	hashBytes, err := bcrypt.GenerateFromPassword(pwByte, bcrypt.DefaultCost)
	return hashEncoder.Encode(hashBytes), err
}

// Verify if a password & bcrypt hash pair is valid
func Verify(pw, signature string, pwEncoder, hashEncoder text_encoder.Encoder) (isHashValid bool, err error) {
	pwByte, err := pwEncoder.Decode(pw)
	if err != nil {
		return false, errors.New(ErrDecodePw + err.Error())
	}
	signatureByte, err := hashEncoder.Decode(signature)
	if err != nil {
		return false, errors.New(ErrDecodeHash + err.Error())
	}

	err = bcrypt.CompareHashAndPassword(signatureByte, pwByte)
	return err == nil, err
}
