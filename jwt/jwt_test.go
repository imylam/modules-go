package jwt

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/imylam/modules-go/crypto_utils/signer"
	"github.com/imylam/modules-go/jwt/signer/jwt_hs256"
	"github.com/imylam/modules-go/jwt/signer/jwt_hs512"
	"github.com/imylam/modules-go/jwt/signer/jwt_ps256"
	"github.com/imylam/modules-go/jwt/signer/jwt_ps512"
	"github.com/imylam/modules-go/jwt/signer/jwt_rs256"
	"github.com/imylam/modules-go/jwt/signer/jwt_rs512"
	"github.com/imylam/modules-go/stringutils"
)

var (
	testPayloadClaims Claims = Claims{"c#": "Microsoft", "golang": "Google"}

	secretKey              = "secret"
	refPkcs1PrivateKeyPem1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxD8FDhP4c9GF8Or8vea+NZqDx/UqqBq+l9Z9Qr0JWVGpMXiG
EwfwQwDAyDibEeT+3naS2Ts1hb1Yt+TywgaVmi8/r2rNFDGmjpUy+/I/7dzZakXE
LLve7sPBBhsDigflRTq0M+QTWt9zRz9rnGhW7diYywbhalEB3RrlIwJsN2oF/AU4
CVGlQwzO/FsOE/od3HEulAcAfFbdJsxRbpwPDFLz68E455ljJfPDXntQxr7QKA+3
+cCP518B6xykTqWMvagkCGq7S2wTKZXFIX/RC3FAjLS3LCdT99+62KlHP4Nhd2M/
BYb4H0rAk1RU7KOw+O88LpOauLUlPUim5jDJWQIDAQABAoIBAQCjx9CJMkONLVTy
frsWJcei5uSKceL6zu83u0to8mkmARAKeIK0yVBMKwm5T/yjD5FhymW+JDsD9cVg
HBQ5t9MNDdfBp4mmC9XsczpMqJ2P/1v35GfXyadBb1/dn5fxj6tZfqe8EuHQWmJU
GOrPawj5kWXbM0/XMeozRGntMO1txHhlXuN+3MaPZBZZJqBD2qKkOQkRU+TjzMUa
DGuHfseSc3prbeIhx9sXZGLm9BYdpej+CGYMJKipscEGiRVPAfmXo8J9tUpQsYiE
cgEFyW2Um1RZ35X4B9pOE8Yolf0U4xqzzU6HBKPMR41CjwLlXsmVK96ap9AYd7fV
EQJj4J5tAoGBAO/MLUV8aX9ImhWteN1ipcvr2y+dTyJcF6MslpA3A2+Zid8+aptW
OvTIpTALe8QnylVBVIUtEDRMrW8g4WDbbnjQY30V2VdDDxTCCJKDh/Ftiex8pSSP
/3OvTTqibttGvkAQI9sJUJTbHpe7PMD+fVRU5pDCMgYUNcDj7ZLyeILHAoGBANGB
hryZdWr91ECvks6VHHEi0FsTBXqN7nI4GQmEa6SWJEkeLKgoHlZBCgYDfGa+LH99
CzAVFDLRFXOw/TIygrUODHsX/oagVv8/QTK/xMshTe88BAWe/QF98ZMiJyFbFUWd
5ai9gJfhU/qNriNZMJDKhP5/8sonRsB4v6aA9DLfAoGANicV0itWZ7gtk9epA9XT
O0n4JbiQtmG1tNPM7KR/0iQKTq/5wzql9cGaDE+Lk7CosLggLjMPBcCLKh1yyDzF
peLplMXqXxp1vWpUJUIu4Qarrww2/xrFxYpBFoy4HCzNqgn7Duv7lqIlNn7CKZNP
GkxSBT7VrSnDOdw/OoAnVuECgYApiRVuVLpLsPEgte5UGIngADfwpm/CoVrxuB92
nJM+uSmOeXX/DJ0fGpvjH1PNhsyJpf/O048CmCM5oZBBIHR7csKUsOgcRrOYvTCu
4AgjAYJS+MIPXzrnzdFUC0RYv5cTCz/Z2WAiPGEK3oX0qh0Px6bgUfuPioPjas0M
NKq1XwKBgGoTJn4BsEGMPIOYf4sHnj4v0IVyi1n27fifdFJSEjxxO6M5gWVd3d5t
eog14W6s9kg77JWss8xf6fMynkXkvaeyzYS2e25e9T1TcFL8Bxe20nqxCm7PX/5/
KXrbNz71H2RMKAE6alsPmLko52WATQnQKrSb+awdEDN4hRVUlIZK
-----END RSA PRIVATE KEY-----`
	refPkcs1PublicKeyPem1 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxD8FDhP4c9GF8Or8vea+NZqDx/UqqBq+l9Z9Qr0JWVGpMXiGEwfw
QwDAyDibEeT+3naS2Ts1hb1Yt+TywgaVmi8/r2rNFDGmjpUy+/I/7dzZakXELLve
7sPBBhsDigflRTq0M+QTWt9zRz9rnGhW7diYywbhalEB3RrlIwJsN2oF/AU4CVGl
QwzO/FsOE/od3HEulAcAfFbdJsxRbpwPDFLz68E455ljJfPDXntQxr7QKA+3+cCP
518B6xykTqWMvagkCGq7S2wTKZXFIX/RC3FAjLS3LCdT99+62KlHP4Nhd2M/BYb4
H0rAk1RU7KOw+O88LpOauLUlPUim5jDJWQIDAQAB
-----END RSA PUBLIC KEY-----`
	refPkcs1PrivateKeyPem2 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnzyis1ZjfNB0bBgKFMSvvkTtwlvBsaJq7S5wA+kzeVOVpVWw
kWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHcaT92whREFpLv9cj5lTeJSibyr/Mr
m/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIytvHWTxZYEcXLgAXFuUuaS3uF9gEi
NQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0e+lf4s4OxQawWD79J9/5d3Ry0vbV
3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWbV6L11BWkpzGXSW4Hv43qa+GSYOD2
QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9MwIDAQABAoIBACiARq2wkltjtcjs
kFvZ7w1JAORHbEufEO1Eu27zOIlqbgyAcAl7q+/1bip4Z/x1IVES84/yTaM8p0go
amMhvgry/mS8vNi1BN2SAZEnb/7xSxbflb70bX9RHLJqKnp5GZe2jexw+wyXlwaM
+bclUCrh9e1ltH7IvUrRrQnFJfh+is1fRon9Co9Li0GwoN0x0byrrngU8Ak3Y6D9
D8GjQA4Elm94ST3izJv8iCOLSDBmzsPsXfcCUZfmTfZ5DbUDMbMxRnSo3nQeoKGC
0Lj9FkWcfmLcpGlSXTO+Ww1L7EGq+PT3NtRae1FZPwjddQ1/4V905kyQFLamAA5Y
lSpE2wkCgYEAy1OPLQcZt4NQnQzPz2SBJqQN2P5u3vXl+zNVKP8w4eBv0vWuJJF+
hkGNnSxXQrTkvDOIUddSKOzHHgSg4nY6K02ecyT0PPm/UZvtRpWrnBjcEVtHEJNp
bU9pLD5iZ0J9sbzPU/LxPmuAP2Bs8JmTn6aFRspFrP7W0s1Nmk2jsm0CgYEAyH0X
+jpoqxj4efZfkUrg5GbSEhf+dZglf0tTOA5bVg8IYwtmNk/pniLG/zI7c+GlTc9B
BwfMr59EzBq/eFMI7+LgXaVUsM/sS4Ry+yeK6SJx/otIMWtDfqxsLD8CPMCRvecC
2Pip4uSgrl0MOebl9XKp57GoaUWRWRHqwV4Y6h8CgYAZhI4mh4qZtnhKjY4TKDjx
QYufXSdLAi9v3FxmvchDwOgn4L+PRVdMwDNms2bsL0m5uPn104EzM6w1vzz1zwKz
5pTpPI0OjgWN13Tq8+PKvm/4Ga2MjgOgPWQkslulO/oMcXbPwWC3hcRdr9tcQtn9
Imf9n2spL/6EDFId+Hp/7QKBgAqlWdiXsWckdE1Fn91/NGHsc8syKvjjk1onDcw0
NvVi5vcba9oGdElJX3e9mxqUKMrw7msJJv1MX8LWyMQC5L6YNYHDfbPF1q5L4i8j
8mRex97UVokJQRRA452V2vCO6S5ETgpnad36de3MUxHgCOX3qL382Qx9/THVmbma
3YfRAoGAUxL/Eu5yvMK8SAt/dJK6FedngcM3JEFNplmtLYVLWhkIlNRGDwkg3I5K
y18Ae9n7dHVueyslrb6weq7dTkYDi3iOYRW8HRkIQh06wEdbxt0shTzAJvvCQfrB
jg/3747WSsf/zBTcHihTRBdAv6OmdhV4/dD5YBfLAkLrd+mX7iE=
-----END RSA PRIVATE KEY-----`
	refPkixPublicKeyPem2 = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnzyis1ZjfNB0bBgKFMSv
vkTtwlvBsaJq7S5wA+kzeVOVpVWwkWdVha4s38XM/pa/yr47av7+z3VTmvDRyAHc
aT92whREFpLv9cj5lTeJSibyr/Mrm/YtjCZVWgaOYIhwrXwKLqPr/11inWsAkfIy
tvHWTxZYEcXLgAXFuUuaS3uF9gEiNQwzGTU1v0FqkqTBr4B8nW3HCN47XUu0t8Y0
e+lf4s4OxQawWD79J9/5d3Ry0vbV3Am1FtGJiJvOwRsIfVChDpYStTcHTCMqtvWb
V6L11BWkpzGXSW4Hv43qa+GSYOD2QU68Mb59oSk2OB+BtOLpJofmbGEGgvmwyCI9
MwIDAQAB
-----END PUBLIC KEY-----`

	jwtHS256Signer          = &jwt_hs256.JwtHS256{}
	jwtHS512Signer          = &jwt_hs512.JwtHS512{}
	jwtRS256Pkcs1PkixSigner = jwt_rs256.NewJwtRS256Pkcs1Pkix()
	jwtRS256Pkcs1Signer     = jwt_rs256.NewJwtRS256Pkcs1()
	jwtRS512Pkcs1PkixSigner = jwt_rs512.NewJwtRS512Pkcs1Pkix()
	jwtRS512Pkcs1Signer     = jwt_rs512.NewJwtRS512Pkcs1()
	jwtPS256Pkcs1PkixSigner = jwt_ps256.NewJwtPS256Pkcs1Pkix()
	jwtPS256Pkcs1Signer     = jwt_ps256.NewJwtPS256Pkcs1()
	jwtPS512Pkcs1PkixSigner = jwt_ps512.NewJwtPS512Pkcs1Pkix()
	jwtPS512Pkcs1Signer     = jwt_ps512.NewJwtPS512Pkcs1()

	refHS256Jwt                 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.2WGdcAREbJ9Ih-I3bCXLYmmeVfrnTbdKIAUmqIxLRfo"
	refHS512Jwt                 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.6rmsBM2QIjq-qnaMbn1Khi-zpm_S1hZiSJMITzmM28ZDX0AywmqCRlGGzVfRmlddKezWVmYwDqb-edX5SsJYdQ"
	refRS256JwtPkcs1     string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.muDiMNErqOZeLavxjDOs6Z7fBhScEcfHt4Obav9Lar003C7NOgWkgnjK7lfPtVlhqJ3il2U11tEijk-Rs93UpZ0WHRT4rC4MgVjCIBDIxUttwPxLb7ax6JTQPTuExqzk8ymSVJUwRYayQ7snnrUNyH9845FzFNBPgLvzS-IfAPSCX5eSeScOue3-0TEBRfbmtnKKbkeALjxBypPlhxkVlsLtkpt4vu09x9WrBcXMnxaNzZn3OJxfLhzfYgoXo5P6xl1fdHbDD-ZfcbqWKYMmYGXGnPgh6v3KroovOvhd345HjhZ-01BD_xAdbwQtrntti714oImdlTDmqXIUWzXYJw"
	refRS256JwtPkcs1Pkix string = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.AH2s9DZt9oRrREB2yPC_Dn167uCa2KBBYAoDtni6KBornZBT1O63FcZje7V3eWEAATPuEgWwIdqaL5yhAenwk3v86vDodyTKbezQgMEa48bNIZRdLSwXiFX9B8v2MnYgJrK_KBGaDKZWstrj_PmlnRbzxOTagZ4nVeDm4BBaPWXtd0V496Z_oq3Joewb9XCUSErNYvZl_ZoiRGGZY1THuQPKuEnp4mbLKy9qsrMh8JgFLYiVtiO-FFLxsHXOD9D0Udv5YNeWDXiF9rtoHh83tQ8RRI9vb0YfbrZnUf7-G_OAuU6V8kIabhIFeVgL2TCaPXhNhjUOpZMEuNFsqdrqfA"
	refRS512JwtPkcs1     string = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.Xzlu9LcpRAVf7Rxuf4G05S6lxObvwRkBfp618QVwy48ncmbB3Y6SJEXp8X00mC4ZXLqL7MnxHFLqnQYyBSCcb2RxE4WlizIjgThDO1hdjpywqLoyGvcDpEm5Gjg0hj9JckJuX4yswYA5DpBxMk1o_OThCspXIjfXb5bRigiq7Y8DjWyS71ejIzLCErpntzOoVwKJBUt3WAwiugXwI-8zcpUmKE7zSH4kkQmze-oALgP2XeVXSrWeAlKuRpsQZm7YgUGksrCCCmxhvZxgMwAaY2V4SCn62ehsHfnYfxt1CAwZxn8NIu_pI6RYoVq8KNLIR1grN_u0IVz3IAIJ-BCPzA"
	refRS512JwtPkcs1Pkix string = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.T7ByTdWP_15VACtoDYkfkjdmkhJbH55_4AaRRfAQRB4YV2-pT14tnO9XcZPPBwXs3H1vYXirHY1Cjm4uY0pWIPAQT26xJQZW9O7c-rF2WdOZST_TBJWaMjCPqNa6wSeEPTeiRsod33_VP5WPIx1hwXBrLLw_UIOpCwEmYweP-CJJIaG10LJHzwm-ckFENxgfFGI5Nu6kcptI3TuVEBlLsmyV9in9bPNC_IaxHtGV3FLRXlaLGHLZO2qloNWDzqmGv5A1ndEK3ggZ00leZe7kaCb0aI3YZhWuX3wkXYoB-qiAmYbxHex-numjuApGX3NERmsnUB4PILrwPDHH4zykpQ"
	refPS256JwtPkcs1Pkix string = "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJjIyI6Ik1pY3Jvc29mdCIsImdvbGFuZyI6Ikdvb2dsZSJ9.EgTzFPEk-Xwf-DDF5oWNKU5JL_u3TrAJ0Bqmd5VYLkfzgrpX38mB69bojtM1_9nlKqvhkVqVtWdK5esiX9tsERNstlouQwuHhFogJ7S_GNuOCTCsdWzM531Ujv92lZuk93GqLVctNn2IpRc3txfn-LQ7ojUpsbiANxmKzzxDxmYpuIQKmAgVvtfXVZm1znFM-8hB9m98Cpnz_zwPyE-cRrL-TQ7nXNyK6N7NZwAJ43MdQ2J8lqFeBFO-5qjQ_4UPPLSJ29f2xk7kYeULsQ6KS8DPmaA-6GDPK4kkZUxHvLJVlcCSRBFZBMYS_IwkrsM0dbnQjCdXQo58hF7y5inj-w"
)

func TestTokenAgainstReference(t *testing.T) {

	type args struct {
		key string //PrivateKey
	}

	testCases := []struct {
		name   string
		signer signer.Signer
		args   args
		want   string
	}{
		{
			name:   "GIVEN_algo_HS256_WHEN_TokenWithTestPayloadClaims_THEN_jwt_same_as_ref",
			signer: jwtHS256Signer,
			args:   args{key: secretKey},
			want:   refHS256Jwt,
		},
		{
			name:   "GIVEN_algo_HS256_WHEN_TokenWithTestPayloadClaims_THEN_jwt_same_as_ref",
			signer: jwtHS512Signer,
			args:   args{key: secretKey},
			want:   refHS512Jwt,
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_TokenWithTestPayloadClaims_and_Pkcs1KeysPair_THEN_jwt_same_as_ref",
			signer: jwtRS256Pkcs1Signer,
			args:   args{key: refPkcs1PrivateKeyPem1},
			want:   refRS256JwtPkcs1,
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_TokenWithTestPayloadClaims_and_Pkcs1PkixKeysPair_THEN_jwt_same_as_ref",
			signer: jwtRS256Pkcs1PkixSigner,
			args:   args{key: refPkcs1PrivateKeyPem2},
			want:   refRS256JwtPkcs1Pkix,
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_TokenWithTestPayloadClaims_and_Pkcs1KeysPair_THEN_jwt_same_as_ref",
			signer: jwtRS512Pkcs1Signer,
			args:   args{key: refPkcs1PrivateKeyPem1},
			want:   refRS512JwtPkcs1,
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_TokenWithTestPayloadClaims_and_Pkcs1PkixKeysPair_THEN_jwt_same_as_ref",
			signer: jwtRS512Pkcs1PkixSigner,
			args:   args{key: refPkcs1PrivateKeyPem2},
			want:   refRS512JwtPkcs1Pkix,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtToken, err := Token(tc.signer, tc.args.key, testPayloadClaims)

			if err != nil {
				t.Errorf("Expect err to be nil, got: %s", err.Error())
			}
			if jwtToken != tc.want {
				t.Errorf("Expect jwtToken: %s, got: %s", tc.want, jwtToken)
			}
		})
	}
}

func TestVerifyWithReference(t *testing.T) {

	type args struct {
		key    string //PublicKey
		refJwt string
	}

	testCases := []struct {
		name   string
		signer signer.Signer
		args   args
	}{
		{
			name:   "GIVEN_algo_HS256_WHEN_VerifyWithRefJwt_THEN_success",
			signer: jwtHS256Signer,
			args:   args{key: secretKey, refJwt: refHS256Jwt},
		},
		{
			name:   "GIVEN_algo_HS512_WHEN_VerifyWithRefJwt_THEN_success",
			signer: jwtHS512Signer,
			args:   args{key: secretKey, refJwt: refHS512Jwt},
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_VerifyWithRefJwt_and_Pkcs1KeysPair_THEN_success",
			signer: jwtRS256Pkcs1Signer,
			args:   args{key: refPkcs1PublicKeyPem1, refJwt: refRS256JwtPkcs1},
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_VerifyWithRefJwt_and_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtRS256Pkcs1PkixSigner,
			args:   args{key: refPkixPublicKeyPem2, refJwt: refRS256JwtPkcs1Pkix},
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_VerifyWithRefJwt_and_Pkcs1KeysPair_THEN_success",
			signer: jwtRS512Pkcs1Signer,
			args:   args{key: refPkcs1PublicKeyPem1, refJwt: refRS512JwtPkcs1},
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_VerifyWithRefJwt_and_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtRS512Pkcs1PkixSigner,
			args:   args{key: refPkixPublicKeyPem2, refJwt: refRS512JwtPkcs1Pkix},
		},
		// {
		// 	name:   "GIVEN_algo_PS256_WHEN_VerifyWithRefJwt_and_Pkcs1KeysPair_THEN_success",
		// 	signer: jwtPS256Pkcs1Signer,
		// 	args:   args{key: refPkcs1PublicKeyPem1, refJwt: refPS256JwtPkcs1Pkix},
		// },
		{
			name:   "GIVEN_algo_PS256_WHEN_VerifyWithRefJwt_and_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtPS256Pkcs1PkixSigner,
			args:   args{key: refPkixPublicKeyPem2, refJwt: refPS256JwtPkcs1Pkix},
		},
		// {
		// 	name:   "GIVEN_algo_PS512_WHEN_VerifyWithRefJwt_and_Pkcs1KeysPair_THEN_success",
		// 	signer: jwtPS512Pkcs1Signer,
		// 	args:   args{key: refPkcs1PublicKeyPem1, refJwt: refPS512JwtPkcs1},
		// },
		// {
		// 	name:   "GIVEN_algo_PS512_WHEN_VerifyWithRefJwt_and_Pkcs1PkixKeysPair_THEN_success",
		// 	signer: jwtPS512Pkcs1PkixSigner,
		// 	args:   args{key: refPkixPublicKeyPem2, refJwt: refPS512JwtPkcs1Pkix},
		// },
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payloadClaims, err := Verify(tc.signer, tc.args.key, tc.args.refJwt)

			if err != nil {
				t.Errorf("Failed to verify reference, got error: %s", err.Error())
			}
			if !reflect.DeepEqual(testPayloadClaims, payloadClaims) {
				t.Errorf("Failed to get back original payload")
			}
		})
	}
}

func TestTokenThenVerify(t *testing.T) {

	type args struct {
		privateKey string
		publicKey  string
	}

	testCases := []struct {
		name   string
		signer signer.Signer
		args   args
	}{
		{
			name:   "GIVEN_algo_HS256_WHEN_TokenThenVerify_THEN_success",
			signer: jwtHS256Signer,
			args:   args{privateKey: secretKey, publicKey: secretKey},
		},
		{
			name:   "GIVEN_algo_HS512_WHEN_TokenThenVerify_THEN_success",
			signer: jwtHS512Signer,
			args:   args{privateKey: secretKey, publicKey: secretKey},
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_TokenThenVerify_with_Pkcs1KeysPair_THEN_success",
			signer: jwtRS256Pkcs1Signer,
			args:   args{privateKey: refPkcs1PrivateKeyPem1, publicKey: refPkcs1PublicKeyPem1},
		},
		{
			name:   "GIVEN_algo_RS256_WHEN_TokenThenVerify_with_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtRS256Pkcs1PkixSigner,
			args:   args{privateKey: refPkcs1PrivateKeyPem2, publicKey: refPkixPublicKeyPem2},
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_TokenThenVerify_with_Pkcs1KeysPair_THEN_success",
			signer: jwtRS512Pkcs1Signer,
			args:   args{privateKey: refPkcs1PrivateKeyPem1, publicKey: refPkcs1PublicKeyPem1},
		},
		{
			name:   "GIVEN_algo_RS512_WHEN_TokenThenVerify_with_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtRS512Pkcs1PkixSigner,
			args:   args{privateKey: refPkcs1PrivateKeyPem2, publicKey: refPkixPublicKeyPem2},
		},
		{
			name:   "GIVEN_algo_PS256_WHEN_TokenThenVerify_with_Pkcs1KeysPair_THEN_success",
			signer: jwtPS256Pkcs1Signer,
			args:   args{privateKey: refPkcs1PrivateKeyPem1, publicKey: refPkcs1PublicKeyPem1},
		},
		{
			name:   "GIVEN_algo_PS256_WHEN_TokenThenVerify_with_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtPS256Pkcs1PkixSigner,
			args:   args{privateKey: refPkcs1PrivateKeyPem2, publicKey: refPkixPublicKeyPem2},
		},
		{
			name:   "GIVEN_algo_PS512_WHEN_TokenThenVerify_with_Pkcs1KeysPair_THEN_success",
			signer: jwtPS512Pkcs1Signer,
			args:   args{privateKey: refPkcs1PrivateKeyPem1, publicKey: refPkcs1PublicKeyPem1},
		},
		{
			name:   "GIVEN_algo_PS512_WHEN_TokenThenVerify_with_Pkcs1PkixKeysPair_THEN_success",
			signer: jwtPS512Pkcs1PkixSigner,
			args:   args{privateKey: refPkcs1PrivateKeyPem2, publicKey: refPkixPublicKeyPem2},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jwtToken, _ := Token(tc.signer, tc.args.privateKey, testPayloadClaims)

			payloadClaims, err := Verify(tc.signer, tc.args.publicKey, jwtToken)

			if err != nil {
				t.Errorf("Failed to verify own signed jwtToken, got error: %s", err.Error())
			}
			if !reflect.DeepEqual(testPayloadClaims, payloadClaims) {
				t.Errorf("Failed to get back original payload")
			}
		})
	}
}

func TestTokenErrorHandling(t *testing.T) {
	key := stringutils.RandomString(30)

	t.Run("GIVEN_not-json-marshalable-payload-claims_WHEN_Token_THEN_throw-err", func(t *testing.T) {
		jwtSigner := &jwt_hs256.JwtHS256{}

		claims := Claims{"a": jwtSigner.Sign, "b": "456"}
		jwtToken, err := Token(jwtSigner, key, claims)

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if jwtToken != "" {
			t.Errorf("Expected token to be empty, got %s", jwtToken)
		}
	})

	t.Run("GIVEN_invalid-key_WHEN_Sign_THEN_throw-err", func(t *testing.T) {
		jwtToken, err := Token(jwt_ps256.NewJwtPS256Pkcs1(), key, testPayloadClaims)

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if jwtToken != "" {
			t.Errorf("Expected token to be empty, got %s", jwtToken)
		}
	})
}

func TestVerifyErrorHandling(t *testing.T) {
	jwtSigner := &jwt_hs256.JwtHS256{}
	key := stringutils.RandomString(30)

	t.Run("GIVEN_malformatted-jwtToken_WHEN_Verify_THEN_throw-err", func(t *testing.T) {
		payloadClaims, err := Verify(jwtSigner, key, "123456")

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if payloadClaims != nil {
			t.Errorf("Expected payloadClaims to be nil")
		}
	})

	t.Run("GIVEN_invalid-header-in-token_WHEN_Verify_THEN_throw-err", func(t *testing.T) {
		payloadClaims, err := Verify(jwtSigner, key, "123.456.789")

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if payloadClaims != nil {
			t.Errorf("Expected payloadClaims to be nil")
		}
	})

	t.Run("GIVEN_invalid-payload-in-token_WHEN_Verify_THEN_throw-err", func(t *testing.T) {
		b64HeaderClaimsStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		b64PayloadClaimsStr := base64.RawURLEncoding.EncodeToString([]byte("abc"))
		jwtToken := b64HeaderClaimsStr + "." + b64PayloadClaimsStr + "." + "signature"

		payloadClaims, err := Verify(jwtSigner, key, jwtToken)

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if payloadClaims != nil {
			t.Errorf("Expected payloadClaims to be nil")
		}
	})

	t.Run("GIVEN_invalid-payload-in-token_WHEN_Verify_THEN_throw-err", func(t *testing.T) {
		b64HeaderClaimsStr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
		b64PayloadClaimsStr := base64.RawURLEncoding.EncodeToString([]byte("abc"))
		signature, _ := jwtSigner.Sign(key, b64HeaderClaimsStr+"."+b64PayloadClaimsStr)
		jwtToken := b64HeaderClaimsStr + "." + b64PayloadClaimsStr + "." + signature

		payloadClaims, err := Verify(jwtSigner, key, jwtToken)

		if err == nil {
			t.Errorf("Expected err, got nil")
		}
		if payloadClaims != nil {
			t.Errorf("Expected payloadClaims to be nil")
		}
	})
}

func TestGetRawSegmentsFromToken(t *testing.T) {
	testHeader := "header"
	testPayload := "payload"
	testSignature := "signature"

	t.Run("success", func(t *testing.T) {
		str := testHeader + "." + testPayload + "." + testSignature
		rawHeader, rawPayload, rawSignature, err := getRawSegmentsFromToken(str)

		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}
		if rawHeader != testHeader {
			t.Errorf("Expect %s, got %s", testHeader, rawHeader)
		}
		if rawPayload != testPayload {
			t.Errorf("Expect %s, got %s", testPayload, rawPayload)
		}
		if rawSignature != testSignature {
			t.Errorf("Expect %s, got %s", testSignature, rawSignature)
		}
	})

	t.Run("GIVEN_string-with-invalid-format_WHEN_get-raw-segments_THEN_throw-err", func(t *testing.T) {
		str := testHeader + "." + testPayload + testSignature
		rawHeader, rawPayload, rawSignature, err := getRawSegmentsFromToken(str)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if rawHeader != "" {
			t.Errorf("Expect empty string, got %s", rawHeader)
		}
		if rawPayload != "" {
			t.Errorf("Expect empty string, got %s", rawPayload)
		}
		if rawSignature != "" {
			t.Errorf("Expect empty string, got %s", rawSignature)
		}
	})
}

func TestVerifyHeader(t *testing.T) {
	signer := &jwt_hs256.JwtHS256{}

	t.Run("success", func(t *testing.T) {
		header, _ := json.Marshal(Claims{"alg": "HS256", "typ": "JWT"})
		b64RawUrlHeader := base64.RawURLEncoding.EncodeToString(header)
		err := verifyHeader(signer, b64RawUrlHeader)

		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}
	})

	t.Run("GIVEN_wrong-header-algo_WHEN_verify-header_THEN_throw-err", func(t *testing.T) {
		header, _ := json.Marshal(Claims{"alg": "HS512", "typ": "JWT"})
		b64RawUrlHeader := base64.RawURLEncoding.EncodeToString(header)
		err := verifyHeader(signer, b64RawUrlHeader)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if err.Error() != ERR_WRONG_HEADER_ALGO {
			t.Errorf("Expect err msg: %s, got %s", ERR_WRONG_HEADER_ALGO, err.Error())
		}
	})

	t.Run("GIVEN_wrong-header-type_WHEN_verify-header_THEN_throw-err", func(t *testing.T) {
		header, _ := json.Marshal(Claims{"alg": "HS256", "typ": "ABC"})
		b64RawUrlHeader := base64.RawURLEncoding.EncodeToString(header)
		err := verifyHeader(signer, b64RawUrlHeader)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if err.Error() != ERR_WRONG_HEADER_TYPE {
			t.Errorf("Expect err msg: %s, got %s", ERR_WRONG_HEADER_TYPE, err.Error())
		}
	})

	t.Run("GIVEN_invalid-rawHeader-str_WHEN_verify-header_THEN_throw-err", func(t *testing.T) {
		err := verifyHeader(signer, "abc")

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
	})
}

func TestGetClaimsFromRaw(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		claims := Claims{"abc": "123", "xyz": "987"}
		claimsBytes, _ := json.Marshal(claims)
		b64RawUrlClaimsStr := base64.RawURLEncoding.EncodeToString(claimsBytes)

		payloadClaims, err := getClaimsFromRaw(b64RawUrlClaimsStr)

		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}
		if !reflect.DeepEqual(payloadClaims, claims) {
			t.Errorf("Failed to get headerClaims")
		}
	})

	t.Run("GIVEN_wrongly-encoded-raw-str_WHEN_get-claims-from-raw_THEN_throw-err", func(t *testing.T) {

		claims := Claims{"abc": "123", "xyz": "987"}
		claimBytes, _ := json.Marshal(claims)
		utf8RawClaimsStr := string(claimBytes)

		claminsGot, err := getClaimsFromRaw(utf8RawClaimsStr)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if !strings.Contains(err.Error(), ERR_DECODED_RAW_STR) {
			t.Errorf("Expect err msg contains: %s, got: %s", ERR_DECODED_RAW_STR, err.Error())
		}
		if claminsGot != nil {
			t.Errorf("Expect headerClaims to be nil, got sth")
		}
	})

	t.Run("GIVEN_invalid-raw-str_WHEN_get-claims-from-raw_THEN_throw-err", func(t *testing.T) {
		claimsGot, err := getClaimsFromRaw("abc")

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if !strings.Contains(err.Error(), ERR_UNMARSAL_DECODED_STR) {
			t.Errorf("Expect err msg contains: %s, got: %s", ERR_UNMARSAL_DECODED_STR, err.Error())
		}
		if claimsGot != nil {
			t.Errorf("Expect headerClaims to be nil, got sth")
		}
	})
}
