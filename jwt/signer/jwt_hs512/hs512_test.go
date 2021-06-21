package jwt_hs512

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer"
	"github.com/imylam/modules-go/jwt/signer/hmac"
)

var (
	testKey       = "i am a secret key"
	testSignature = "zMPOnWEB64XtZC_y7tYSWl6v2pyoydhxPLuEQ15ysxkhYoSdZnc-n0lBcT00_GjOwW0XNQO-YlpDZtcw-XeJCA"

	jwtSigner = JwtHS512{}
)

func TestAlgo(t *testing.T) {
	signer.SharedTestAlgo(t, &jwtSigner, ALGO)
}

func TestSignScheme(t *testing.T) {
	signer.SharedTestSignScheme(t, &jwtSigner, ALGO)
}

func TestSignAgainstStandard(t *testing.T) {
	signer.SharedTestSignAgainstReference(t, &jwtSigner, testKey, testSignature)
}

func TestVerifyAgainstStandard(t *testing.T) {
	signer.SharedTestVerifyAgainstReference(t, &jwtSigner, testKey, testSignature)
}

func TestSignThenVerifyWithRandomInputs(t *testing.T) {
	signer.SharedTestHmacSignThenVerifyWithRandomInputsTest(t, &jwtSigner, hmac.ERR_INVALID_SIGNATURE)
}
