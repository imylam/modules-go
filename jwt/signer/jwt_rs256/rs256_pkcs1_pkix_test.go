package jwt_rs256

import (
	"testing"

	"github.com/imylam/modules-go/crypto_utils/rsa/sign_scheme"
	"github.com/imylam/modules-go/jwt/signer"
)

var (
	pkixSignature       = "kVi-i7IY3yUexi9VzRBWTbTvJJAQwPRt4Ti-lC_DGH0AcW_A51VQ7EXTsq4kKKfOS2aP-EbGiO7qVorWEE-ht3Ai5kwF6li2hLG8nCnueHp936Rr1IoqZ5YQibAhTdkvnP4hz1pSlAlZUdSVapcTQjXqLEfHumHlGAfOe40lyXtRIxMKY9OF1VswoVvKehmF_4P45fwKc_amQrrzF2HymExQU7IMb20zxr6IFg8QOhEhs8TqDWU8tTOQqz1szHkMsp8qpB7vmjgHGqbhDxWSDb66RAz2IA5JC2jkenXfM2svCPyyCpHY-jXAvA4Lbi_-h9Aq_BJp0EQSUX6tG_D3sg"
	pkcs1PrivateKeyPem2 = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAy/89CQpSjXAVxj5kwbEB25YlLVbJ4LCgmjTdUweBitinYRm6
9dDnVmvPgIlyMuZu0YLb+MxilYv5KOxGou0nhtCTTtOqcjLcy6IAsQXANs/iH21u
YAAVBIBvYXb5i7L/73s7B2xAl7fj7s8ZdqEJaQMrfWfPHz3yDGHB6x2qE0Ai1D4E
0WOsYCtkITLa0J7+u0MvQvwshTsl7dnLBjAInyLFFsEHnKtDuZnsnWCGB2KRFJd7
P/2DlaAU9fDo8xIlyoox8BL1HitZGe6ArJuKx8dqiu3fSWVbFEUNsx9Qu8OKumu4
FOqBqTFfaljK4uhQUvueZsdsdQxSOuHlCPcJlwIDAQABAoIBAHOOTgDE/CZqi6sU
xPaDUk4VK1IXi5vf8dnogEb8RYFlYMs8TA/bGnB1+cESGsKCjdvYiMrS3DViaO2p
ignY1T8k/4zzkeXGshQX3NRqMYvbDnhHAPMYmM9IAc/wGUPtTdVWtQVraNuIq3En
l4D/j9kQlp4fI9DKwkYJSlPpJeJou2kwAc1JH/uye6pbpWIOetyvhJh7p4fN1rJj
7D9KMRrDVH/ImZ1NqxnnlC08QGKb1hbFw8B4ynyHwvDPKxw49YTlXrouadenC86w
eDmu6TC0HurHtc2RP4mitrqFQCb0reQCkKiB71vBr0FbVL0YiccabCxWVKo2PpHI
n/e2zwECgYEA5i3hIm2h0NPzAL2TFST8MWBEMver1e5UWtzg4kcfdWJAO6ZBF7Id
Y1p2BnoUYzZgpunob1CTBid0WefRSWVJYiuWlouf18jtcR8KrlQHHv+3Nwt2/Pv4
h2Ip4fwMeDaXwkhRIXB/YkWcF3BvMBvZUdyLdCqazA14CzbqZMydA6ECgYEA4uF6
S4cueL0p2zR2Jp0gy8n5fNUB8lQAtEfteLVr33inn8m5VAe+AaPU4uCgMtKUBK8O
hbo0RLzZrJj9lgq1TlL+ucO9647+t3oL9ncXwKhjgVFazNyIkWvA3FmC7PU8aOuT
yNmi3od2M6BcCHIQ2Y8Kf4ftnpui5CEgucy0AjcCgYB4WHqCPqHBBl/h/jwdbQXy
ZuuhXj7YjlBKZXuqsxbuj50X0tfrpLOa05wrzL5GFRM5kch2EsGcERrTOtIAttVE
X5fPRFchQitq3pj+Bm7mtTo8rGDc6nzJg/hz8A0w+RIlgRvyCNiBL/Xph16K37Sj
CVVcOj5O+6fM7Txl0VkyoQKBgF1N7UVyaqIs6THE+XIX3Izymy/DSfGmqkN58Sdb
NOnKbOVByH3OUU3LWpmTV06PW2Axvf8w/J3oLHzWzjMOZFG5wBgVb92YCRjbkF/j
yljo50MfegAWEfP8JGx6Q2W/1QAxIa3QEzMA8pN4t2ChyFwwf1jDRe2cg/jdxt+i
V8UxAoGAeNfBbrpIHeD3LeScBHATfzc+sww2go/JQQ/Lofw3eA/CVDAR7Zx3gas9
AX0SvAg9uPC2eDwIq4fXlG6VVkgRbQVTgag9qaOY6jKI0wH/f/6QinDPb5mtYig+
IFH31TLHvOd8iQhPwH+V6CZo9XulEgPMMXN7QOwCsjogIi43VNY=
-----END RSA PRIVATE KEY-----`
	pkixPublicKeyPem2 = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/89CQpSjXAVxj5kwbEB
25YlLVbJ4LCgmjTdUweBitinYRm69dDnVmvPgIlyMuZu0YLb+MxilYv5KOxGou0n
htCTTtOqcjLcy6IAsQXANs/iH21uYAAVBIBvYXb5i7L/73s7B2xAl7fj7s8ZdqEJ
aQMrfWfPHz3yDGHB6x2qE0Ai1D4E0WOsYCtkITLa0J7+u0MvQvwshTsl7dnLBjAI
nyLFFsEHnKtDuZnsnWCGB2KRFJd7P/2DlaAU9fDo8xIlyoox8BL1HitZGe6ArJuK
x8dqiu3fSWVbFEUNsx9Qu8OKumu4FOqBqTFfaljK4uhQUvueZsdsdQxSOuHlCPcJ
lwIDAQAB
-----END RSA PUBLIC KEY-----`

	JwtRS256Pkcs1PkixSigner = NewJwtRS256Pkcs1Pkix()
)

func TestAlgoRS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestAlgo(t, JwtRS256Pkcs1PkixSigner, ALGO)
}

func TestSignSchemeRS256Pkix(t *testing.T) {
	signer.SharedTestSignScheme(t, JwtRS256Pkcs1PkixSigner, sign_scheme.PKCSv1_5)
}

func TestSignAgainstReferenceRS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestSignAgainstReference(t, JwtRS256Pkcs1PkixSigner, pkcs1PrivateKeyPem2, pkixSignature)
}

func TestVerifyAgainstReferenceRS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestVerifyAgainstReference(t, JwtRS256Pkcs1PkixSigner, pkixPublicKeyPem2, pkixSignature)
}

func TestSignThenVerifyWithRandomInputsRS256Pkcs1Pkix(t *testing.T) {
	signer.SharedTestRsaSignThenVerifyWithRandomInputsTest(t, JwtRS256Pkcs1PkixSigner, pkcs1PrivateKeyPem2, pkixPublicKeyPem2, "crypto/rsa: verification error")
}
