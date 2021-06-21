package jwt

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer/jwt_hs256"
	"github.com/imylam/modules-go/stringutils"
)

var (
	testHS256JwtString string = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.2WGdcAREbJ9Ih-I3bCXLYmmeVfrnTbdKIAUmqIxLRfo"

	jwtHS256Signer = &jwt_hs256.JwtHS256{}
)

func TestHS256TokenAgainstStandard(t *testing.T) {
	SharedTestTokenAgainstStandard(t, jwtHS256Signer, secretKey, testHS256JwtString)
}

func TestHS256TokenThenVerify(t *testing.T) {
	key := stringutils.RandomString(30)
	SharedTestTokenThenVerify(t, jwtHS256Signer, key, key)
}
