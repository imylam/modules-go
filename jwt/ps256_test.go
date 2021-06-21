package jwt

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer/jwt_ps256"
)

var (
	testPS256JwtString string = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.EgTzFPEk-Xwf-DDF5oWNKU5JL_u3TrAJ0Bqmd5VYLkfzgrpX38mB69bojtM1_9nlKqvhkVqVtWdK5esiX9tsERNstlouQwuHhFogJ7S_GNuOCTCsdWzM531Ujv92lZuk93GqLVctNn2IpRc3txfn-LQ7ojUpsbiANxmKzzxDxmYpuIQKmAgVvtfXVZm1znFM-8hB9m98Cpnz_zwPyE-cRrL-TQ7nXNyK6N7NZwAJ43MdQ2J8lqFeBFO-5qjQ_4UPPLSJ29f2xk7kYeULsQ6KS8DPmaA-6GDPK4kkZUxHvLJVlcCSRBFZBMYS_IwkrsM0dbnQjCdXQo58hF7y5inj-w"
)

func TestPS256VerifyWithReference(t *testing.T) {
	SharedTestVerifyWithReference(t, jwt_ps256.NewJwtPS256Pkcs1Pkix(), refPkixPublicKeyPem2, testPS256JwtString)
}

func TestPS256TokenThenVerify(t *testing.T) {
	SharedTestTokenThenVerify(t, jwt_ps256.NewJwtPS256Pkcs1(), refPkcs1PrivateKeyPem1, refPkcs1PublicKeyPem1)
}
