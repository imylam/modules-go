package jwt

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer/jwt_hs512"
	"github.com/imylam/modules-go/stringutils"
)

var (
	testHS512JwtString string = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.6rmsBM2QIjq-qnaMbn1Khi-zpm_S1hZiSJMITzmM28ZDX0AywmqCRlGGzVfRmlddKezWVmYwDqb-edX5SsJYdQ"

	jwtHS512Signer = &jwt_hs512.JwtHS512{}
)

func TestHS512TokenAgainstStandard(t *testing.T) {
	SharedTestTokenAgainstStandard(t, jwtHS512Signer, secretKey, testHS512JwtString)
}

func TestHS512TokenThenVerify(t *testing.T) {
	key := stringutils.RandomString(30)
	SharedTestTokenThenVerify(t, jwtHS512Signer, key, key)
}
