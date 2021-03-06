package jwt_ps256

import (
	"testing"

	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/jwt/signer"
)

var (
	pkcs1Signature      = "Nik24wZtREcmELsCjekV7O8gq95M3ZYor4N1hbpauIv1penlppssIdFjAl4CqjDfMz6ImhFWSYeLGZ5HEBeQfcTfsTad_k-TOKJCkJRutZGBTjG_P01Bu9tQl8EgQU4pUNyLIqg9S-0Ac2EVW2-aogum1PAbCaSZBt5Ge7EwZ7KvwH3YvxKGbrnDJPxHQ5DpESE4QN_-CuDTZLjI9WI6bsCbbxbyRFbbmj2NPzyoiSfrke04yc8HAyg5JGnpG8yEXJZTGmXXCxqtijwgQ-r3Agg2IiE59rhgp4wvLwFAuwFY308v51K6UD21GisrFLzLmNx8vX5KLL0mo6_vMjImMg"
	pkcs1PrivateKeyPem1 = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAxoHMB/ztvZAuI5GkVbYwdidTfd+qGcVXv0LbKkQcHtGSwrNe
mv62IoGx1zVOXIkUGa2yYNJqWqKxDFkFAol9jNGbcRTqfT9y2dUwVGKlD7ougGXe
HaQyVAhCLhukbJ4sxkrldoLTUzcD8j3Lv14r0xWLiOkJc9nY2D18Xg8c6B5w5+m2
8On7018LDCAf6E+xQZKiEZ8cJB4fDoHIi+JPU0qfZrOTN3AAVqxvDKJTPB7P211T
F1j9uiTd27Z2q/wC+kOGGZygYYRoJRxdjw/X+qvt8eOzlXPVGwTOK+U3fIAFwZ5z
CXnVgB3cSkrrLRVS7HnlIFMHdgJFuTTmVdXZDQIDAQABAoIBAD4PTENfDtCJ5/LU
0KS/Tc1SpCahK2PdL36rHyvKmWQFLzXRsA0S/sww8fGPR81kSbVxeWgNwJRPcryi
hA9z/p1s1oT2/gxkLrrtjKuFH4eYNHuN3XA06ksdPdt+ZtxSYzsnJS/03K6Sb5hn
O3C7t0XJ4ZLPEFZ4z/Ni3aPmY6opdOo9SNq/41TQMpvXkFKj0klxYP7WW8wB+CiB
8bqon4zXDsyttsf6Ou0IiVw0vnhpeJnWKsG9KMtigzZg0dsidR5jXM9RDtftXswr
rpAu6ebP9nnoVaAYO0FL1DsaQsZd47fD0ZiGLD9e5Oq44MfsUSiEMe8KA+eparZh
/Vhraj0CgYEA8S/g1MPCXUvTu02CMP15dHjltmbphA64gyck3KpYYFXic4EtHRoF
xoAN3hE22z/BPGNA9aMUokUW+Ce2Eutddnm6UW16hdU0h+9ZJeUSK6FTIOG27HMi
z7dcz7Ah5y6d/AU9BaDAP7sUkh2YAOE84pf7Kr5Btuxzm3ne65CXBK8CgYEA0rLf
OcMxKf81wZ56mMPgjw6S7TA/Ccqh98hM41PFjgOiU068Lpml0D50mtfvIJwYl/0E
jjvhXnySeBPiTMm/t/W9riKx/Qx6X4KCpi39TB6mPQcxmBY8cC+Nlirq1dmmlo2k
99tApBtIu7eNjOPKO0SY/GN+HhN3uG5ho+20pQMCgYB+y+LxODE4hyK695aYVsnB
V8W8TQI68NpD6RJSCCQKEVzJyIGFKSccIjooIvip7yyRqMR/3sp8PMJEl+v6qk4q
ePhg0qN1NI83X7eIWpNg6KEhSki2qhkFBqr+bOSF+1YHJmHcUZSAbMP1xSUiYUd3
ANuErx0xI8HrXPi68vrR9QKBgQCmOELumNSSYyoPg20IU482jLLQt/0jRl6c0cIG
nTH/JVLMEhNXWBN9w6fN+IhH251zWkJby1WyauhKHrWrCoZbJFztoaV1EoEAFD/p
xeJMSOmwv5oad4BaqMk0LMtyxfAsWbZJawkF7hhlLxtWiOYj96wRgJQgOg96ymnx
Hzgh7QKBgD5maV6Lo9KkQ1j4+lFYjM2DFlhkQZOmfVLW85K17iMBjnWu5443SZpC
2tI9h0QKe+o4wQwZ5SbjAbNAvZG3QwrsgioOtn5bcP5ERFVsckeKDG4o+JZVIcOu
1vkeJ5QNEW0hiXPpI7CfxVdyo9fJEyCdIkFeqbxf0AMmIKdHwD4R
-----END RSA PRIVATE KEY-----`
	pkcs1PublicKeyPem2 = `-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAxoHMB/ztvZAuI5GkVbYwdidTfd+qGcVXv0LbKkQcHtGSwrNemv62
IoGx1zVOXIkUGa2yYNJqWqKxDFkFAol9jNGbcRTqfT9y2dUwVGKlD7ougGXeHaQy
VAhCLhukbJ4sxkrldoLTUzcD8j3Lv14r0xWLiOkJc9nY2D18Xg8c6B5w5+m28On7
018LDCAf6E+xQZKiEZ8cJB4fDoHIi+JPU0qfZrOTN3AAVqxvDKJTPB7P211TF1j9
uiTd27Z2q/wC+kOGGZygYYRoJRxdjw/X+qvt8eOzlXPVGwTOK+U3fIAFwZ5zCXnV
gB3cSkrrLRVS7HnlIFMHdgJFuTTmVdXZDQIDAQAB
-----END RSA PUBLIC KEY-----`

	jwtPS256Pkcs1Signer = NewJwtPS256Pkcs1()
)

func TestAlgo(t *testing.T) {
	signer.SharedTestAlgo(t, jwtPS256Pkcs1Signer, ALGO)
}

func TestSignSchemePkcs1(t *testing.T) {
	signer.SharedTestSignScheme(t, jwtPS256Pkcs1Signer, sign_scheme.PSS)
}

func TestVerifyAgainstStandardPkcs1(t *testing.T) {
	signer.SharedTestVerifyAgainstReference(t, jwtPS256Pkcs1Signer, pkcs1PublicKeyPem2, pkcs1Signature)
}

func TestSignThenVerifyWithRandomInputsPkcs1(t *testing.T) {
	signer.SharedTestRsaSignThenVerifyWithRandomInputsTest(t, jwtPS256Pkcs1Signer, pkcs1PrivateKeyPem1, pkcs1PublicKeyPem2, "crypto/rsa: verification error")
}
