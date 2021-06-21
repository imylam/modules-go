package jwt

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer/jwt_ps512"
)

var (
	jwtRS512Signer = jwt_ps512.NewJwtPS512Pkcs1()
)

func TestPS512TokenThenVerify(t *testing.T) {
	SharedTestTokenThenVerify(t, jwtRS512Signer, refPkcs1PrivateKeyPem1, refPkcs1PublicKeyPem1)
}
