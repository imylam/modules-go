package jwt_ps256

import (
	"testing"

	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/jwt/signer"
)

var (
	pkixSignature       = "HCeosHKx7i-_umx77WVKhgMAkGrp37j8i1AM9MDBaBLa0CbMI7-xM7uL98hgz-wRShij7vWc_q2TCwHzPlS67tkcoEAGmdttHlBT0MjxpEL9toiU7CggY90uzJxxkEW_qzcOgRhFx8J9rfx3M02zxBOXNCSbhnj4m2fove1GbqRe-FTBD6YTwVQXMOAZFSOxd8I8ITXNHs_puW7brDfN8JzsiU9UYk353RuNEqSSDWV8pZOq2Nyxg_2Bpi48UIWlZmar8cd6jwA9ZFv4LHEwpuoVXCMObOc5VYBSmgJXBMr6R1nPFjWnyB5s2ABKgJQoqOHaR0C3MZFzfHLNpsseEQ"
	pkcs1PrivateKeyPem2 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAlLCFbMxn77JSnpzz4h3dFAEKDrE1nPVE9p/+HXsGSX+e2iaQ
KXoFRCtzmw74Hs50Qi0JgtjYb3z8Tq7Xz48xq5V4MIeWhM7bSpI5e9UPCbD5jo7V
qgjb9p3u/yFa3AO21mBd4sSYBC1if8Zfr6fLGDXMoWt0gC6lZ67fVBCrAQ4rYG+4
4UX7hqFkc29aZj4DZKXEG8JKDdXwA9r4N0whrQUZGNKi0bEzUvxpWVnD+FTN4Rr4
H0po26+AiErF+sWuw1B2BZ2EF4ruoMTuHmCVCBOgNkqbGygOnHdLRMVhkbEpzLRo
WV1uaDnUr/AJIvasqnKv2GqVYzgXoktrmowlhwIDAQABAoIBACLYp7xSvz0GnqQ7
hlCEzS4F/FRrJXRuasYdwtEn5tZMyW64wOpnhVpvkH1TacTWf5qOsX7v0PF36i2K
fltPZMWglvVQoW7oh64XTM9/pDGSPzowsVRTFTHb24oBSCjt2eit1vLxPesks8Pc
OsqQ2WEIIrfl1fzAcdU1v3MVIO5zBzVTh0fpm1aY9wbPs6zHSAiJH6oMYDzKH7c3
+JrvaAn/tEJzHbStI7rDO99QuOWK20f3Cqfc0Y16ROsIWC5EGk4ykCNh9ckR5qdK
w2F0zczgdTNDTFyb8fufKQAplhTsNfoDcIWtYLRu1s57rrATU6JCVyTtm4rRznmN
EMxBzWECgYEAwPH+XALX9iwj6ILHUaprBlt7lF/VuF6p+60Ipj2aw2DAXonz4lXk
fE2giXPr7OpIHDgaBlKXCzOgI1k+YeCePfOWKpcXAZE1YaNsIggoFd1VeOLrzjcj
VC6Fs2wE6pWZxlStqEIeTQ4aaw/iGSYjBc/TGbf9bu6220C02DRG+vECgYEAxUgL
ci34W+wgwEPQ+oqa403IhtqCPaBDw6WdgMesN+wIfLfZkMz1IKEi5MVM5qsMGM2e
C16aLIgcZD7x740S0CmiwRLZ5VSnIJiVVwaIg6wuJJjIfy/rFVe04Pq6QqO2zPSP
lWte03M7YIkx3spfjI8m+MuXdjhHRvWSeD4Kd/cCgYAmUGeoMdBczAsdYsrdxq+W
BZiWsCkqgXHTzlqHWHhhD9djbpWFfnTu0iNs6B4TX7qOD/3q/3+K8+d63X/rw8To
nHRXZMVmxEULbH5Oi7waC2erp7QXsQ9M6igWpv6a7rYokiwh229U8dYBKJhHUjFm
OAy9cLHc035wL3s567ekoQKBgFLfIr/CA9RJarCZTE4Sr2HQqO3NGGzex9iF15Xj
SrrrEd2iNWiYUFh2l/vVzaoQLDK3HS7VfJo8SwDpWCQy9LYw50eHrbSiTNpqfkFi
YzI8v91ruL2E2ZHLmBXx/RBFSWLrUO2JfvoAK+8vcp2OEXkwIUTd8TAeEAME4ZRV
K3ydAoGAQLsu5PVNONke9PKOCOgC5G2pKIoPPjhLGRJWKjmkL1beNwUQE4fRSpBR
EJRlR5PZHv3e+bLrQqr1P+ignm1eUbpgicOiSfvYOS9zUOUVN6lMEVay+VwcyT5n
5TIF9XABas2Ur1E6b3f+tmmEnbEJ1ml2TrajIGBF6vQMRQnpUgA=
-----END RSA PRIVATE KEY-----`
	pkixPublicKeyPem2 = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAlLCFbMxn77JSnpzz4h3d
FAEKDrE1nPVE9p/+HXsGSX+e2iaQKXoFRCtzmw74Hs50Qi0JgtjYb3z8Tq7Xz48x
q5V4MIeWhM7bSpI5e9UPCbD5jo7Vqgjb9p3u/yFa3AO21mBd4sSYBC1if8Zfr6fL
GDXMoWt0gC6lZ67fVBCrAQ4rYG+44UX7hqFkc29aZj4DZKXEG8JKDdXwA9r4N0wh
rQUZGNKi0bEzUvxpWVnD+FTN4Rr4H0po26+AiErF+sWuw1B2BZ2EF4ruoMTuHmCV
CBOgNkqbGygOnHdLRMVhkbEpzLRoWV1uaDnUr/AJIvasqnKv2GqVYzgXoktrmowl
hwIDAQAB
-----END RSA PUBLIC KEY-----`

	jwtPS256Pkcs1PkixSigner = NewJwtPS256Pkcs1Pkix()
)

func TestAlgoPS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestAlgo(t, jwtPS256Pkcs1PkixSigner, ALGO)
}

func TestSignSchemePS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestSignScheme(t, jwtPS256Pkcs1PkixSigner, sign_scheme.PSS)
}

func TestVerifyAgainstReferencePS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestVerifyAgainstReference(t, jwtPS256Pkcs1PkixSigner, pkixPublicKeyPem2, pkixSignature)
}

func TestSignThenVerifyWithRandomInputsPS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestRsaSignThenVerifyWithRandomInputsTest(t, jwtPS256Pkcs1PkixSigner, pkcs1PrivateKeyPem2, pkixPublicKeyPem2, "crypto/rsa: verification error")
}
