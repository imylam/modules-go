package jwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/imylam/modules-go/crypto_utils/signer"
)

const (
	KEY_ALGO       string = "alg"
	KEY_TOKEN_TYPE string = "typ"
	TOKEN_TYPE     string = "JWT"

	ERR_DECODED_RAW_STR      string = "failed to decode raw string: "
	ERR_INVALID_TOKEN_FORMAT string = "token parsing failed: format not valid"
	ERR_UNMARSAL_DECODED_STR string = "failed to unmarshal str to claims: "
	ERR_WRONG_HEADER_ALGO    string = "token parsing failed: algo not matched"
	ERR_WRONG_HEADER_TYPE    string = "token parsing failed: type is not JWT in header"
)

type Claims map[string]interface{}

func Token(signer signer.Signer, key string, claims Claims) (token string, err error) {
	headerClamis := Claims{
		KEY_ALGO:       signer.Algo(),
		KEY_TOKEN_TYPE: TOKEN_TYPE,
	}

	header, err := json.Marshal(headerClamis)
	if err != nil {
		return
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return
	}

	b64Header := base64.RawURLEncoding.EncodeToString(header)
	b64Payload := base64.RawURLEncoding.EncodeToString(payload)

	signature, err := signer.Sign(key, b64Header+"."+b64Payload)
	if err != nil {
		return
	}

	return b64Header + "." + b64Payload + "." + signature, nil
}

func Verify(signer signer.Signer, key, jwtToken string) (payloadClaims Claims, err error) {
	rawHeader, rawPayload, signature, err := getRawSegmentsFromToken(jwtToken)
	if err != nil {
		return
	}

	err = verifyHeader(signer, rawHeader)
	if err != nil {
		return
	}

	err = signer.Verify(key, rawHeader+"."+rawPayload, signature)
	if err != nil {
		return
	}

	payloadClaims, err = getClaimsFromRaw(rawPayload)
	if err != nil {
		return
	}

	return
}

func getRawSegmentsFromToken(jwtToken string) (rawHeader, rawPayload, signature string, err error) {
	rawSegs := strings.Split(jwtToken, ".")

	if len(rawSegs) != 3 {
		err = errors.New(ERR_INVALID_TOKEN_FORMAT)
		return
	}

	rawHeader = rawSegs[0]
	rawPayload = rawSegs[1]
	signature = rawSegs[2]

	return
}

func verifyHeader(signer signer.Signer, rawHeader string) (err error) {
	headerClaim, err := getClaimsFromRaw(rawHeader)
	if err != nil {
		return
	}

	if headerClaim[KEY_TOKEN_TYPE] != TOKEN_TYPE {
		err = errors.New(ERR_WRONG_HEADER_TYPE)
		return
	}

	if headerClaim[KEY_ALGO] != signer.Algo() {
		err = errors.New(ERR_WRONG_HEADER_ALGO)
		return
	}

	return
}

func getClaimsFromRaw(rawStr string) (claims Claims, err error) {
	decodeStr, err := base64.RawURLEncoding.DecodeString(rawStr)
	if err != nil {
		err = errors.New(ERR_DECODED_RAW_STR + err.Error())
		return
	}

	err = json.Unmarshal(decodeStr, &claims)
	if err != nil {
		err = errors.New(ERR_UNMARSAL_DECODED_STR + err.Error())
		return
	}

	return

}
