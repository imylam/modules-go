package signer

import (
	"testing"

	"github.com/imylam/modules-go/crypto_utils/signer"
	"github.com/imylam/modules-go/stringutils"
)

var (
	testMsg               = "I am a plain text"
	randomPkcs1PrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAl1vp4cdX8ggJcR5CxSk90g2UI5gMwR07X2XcK1tbEDTeP9o0
k9HjrsL45RA/WlwjBeWG3vX8Z78iNizCY7VyHUie9BNKnMIO72jrlCfn9QD7dDmu
JFRB1Xfeq7eNSlxWKNa4LqpTuiE1dybG2FYKcJN4nyP4GWqARntPzGl2d9QBWK66
5oW621Pr6vcE7BYd9laiU0A1cJY6B1EqdAWgXkEbXYGjULzGsF+ptprwbL6eUEJ3
kVk/5n69jgj5TeHaaWe62CRxXQSuuEVEzwmEw5dSJwXBf/ohTT2TgUT4d2NE83qM
+ZdUDTNfz3F0UwIEb9sUSlr6Z5Bg60Mi8jvfxQIDAQABAoIBAQCENV/kvDggjE6b
BSCzkSOTwBKeyKiTYlJDMPkQ0hqH3HYpdhMo71QeieXYR8nexs48z1FwnZMcmAJt
KcmeSJZl59IYRmWM6aEcFBx6bCUbiAEcc2meCA79RFg2y/zZcDA+OdflwxehZHKM
Ik3cF8PEs7vP3h5PLQzhA8MfPRui7C9hm1psvU9a/Y+2RtBT0PYRfIwi0KyAIjyr
do0qYmkh7D2pB1PjYuRCU4vYAZzVCyzlixZ9o4t0Zoejnvq+dC5ZrE7pbPRSMDV/
gsIsMzuHtZmnumSl47Eft1EaEJq+4SO4zlgUzsrni3CBAQCZFgDPVYsa57BnfL85
ZfiPBZydAoGBAMPmjfjAkxx8Hq+zaMEg6ELQn6zT2HAcrzZG2HcxYOOnNqNQXRGs
QW5oCMKiaxdRC7ij16+kLFl2eHY+nhN1B7r7f7uyvu86Ctsa+B7Y3r1ig38YnvG3
Prs2S15bQ+kwr5XZOKnRx6KIph3FwerEjiui0jLOdbyf+D9hLz/Je65vAoGBAMXL
MraedeX/qfXcEvJQu/s8hzH2SRmyjbfwc13mIgymj1Rj7l5atmvwx0iNfhUDI3ZZ
QFP7YyQEci3PZ1PaHjJPj4v1E7v/0Im5iVV+pqL/7CpBIuTD98MJ2HxGJVCowpT/
7QgRGBVE0vw6U1Ab0aOD9MAVw8RYlJu9onNb6y8LAoGAfzWuyXJb1SpwTs3k30x8
Ji8NERB7wsmNqWQ12qiQ7yO9Ii3kUb6WupgJ4EHR4tE5GEwkmiS0u99nd/lPcvkS
7QO1vW/j9rqtI/yOVJGlijt3gke9pt7EeJNYO8xt+/YmftsQpY3Y4h10KW8qbkX2
wDU5484XvEXw0U9NfFFc5DcCgYBP1uPTn0cL3hVm7ryfH0Oh+B7CZh2/x7k45FBN
ONXJsXntoKDZaVh1Xa2zdZnNNYUdAo3a2IB+S2UjZLLawBKsUD0rS3P50RsGXOQ4
pHTzGsbjj4NcQFZEXjcKgu4RDu3sYxn0xaGpBCz+LzTuAyyuClfDKYXqPa9O5k8q
rZHTXQKBgQCX0Mmibky9eK/24NSa9x43CDwLKXVM+D3YaymGQoTdlTeaIATdeMe2
O1HJWk++KYzhxVTSszeC9zsNfQ9hKBAdzQF/7I9Pkx+W+G3ARFqlBmcpvi2qz4GK
HaejUqGwfub7Sg0JLLbiYP4zfFiiQB7Tt8RgSah/tI2t+nSud4iWcA==
-----END RSA PRIVATE KEY-----`
)

func SharedTestAlgo(t *testing.T, jwtSigner signer.Signer, expectedAlgo string) {
	algo := jwtSigner.Algo()

	if algo != expectedAlgo {
		t.Errorf("[%s-%s]Expect algo to be: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedAlgo, algo)
	}
}

func SharedTestSignScheme(t *testing.T, jwtSigner signer.Signer, expectedScheme string) {
	scheme := jwtSigner.SignScheme()

	if scheme != expectedScheme {
		t.Errorf("[%s-%s]Expect sign scheme to be: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedScheme, scheme)
	}
}

func SharedTestSignAgainstReference(t *testing.T,
	jwtSigner signer.Signer, testKey, refSignature string) {

	t.Run("success", func(t *testing.T) {
		signature, err := jwtSigner.Sign(testKey, testMsg)

		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}
		if signature != refSignature {
			t.Errorf("[%s-%s]Expect signature: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), refSignature, signature)
		}
	})
}

func SharedTestVerifyAgainstReference(t *testing.T,
	jwtSigner signer.Signer, testKey, refSignature string) {

	t.Run("success", func(t *testing.T) {
		err := jwtSigner.Verify(testKey, testMsg, refSignature)

		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}
	})
}

func SharedTestHmacSignThenVerifyWithRandomInputsTest(t *testing.T,
	jwtSigner signer.Signer, expectedErrMsg string) {

	randomKey := stringutils.RandomString(20)
	randomMsg := stringutils.RandomString(50)

	t.Run("success", func(t *testing.T) {
		signature, err := jwtSigner.Sign(randomKey, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(randomKey, randomMsg, signature)

		if err != nil {
			t.Errorf("[%s-%s]Cannot verify own signature, err got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}
	})

	t.Run("GIVEN_different-msg_WHEN_verify_THEN_return-err", func(t *testing.T) {
		randomMsg2 := stringutils.RandomString(20)
		signatureOfAnotherMsg, err := jwtSigner.Sign(randomKey, randomMsg2)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(randomKey, randomMsg, signatureOfAnotherMsg)

		if err == nil {
			t.Errorf("[%s]-%sExpect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})

	t.Run("GIVEN_signature-of-another-key_WHEN_verify_THEN_return-err", func(t *testing.T) {
		randomKey2 := stringutils.RandomString(20)
		signatureOfAnotherKey, err := jwtSigner.Sign(randomKey2, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(randomKey, randomMsg, signatureOfAnotherKey)

		if err == nil {
			t.Errorf("[%s-%s]Expect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})

	t.Run("GIVEN_invalid-signature_WHEN_verify_THEN_return-err", func(t *testing.T) {
		_, err := jwtSigner.Sign(randomKey, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		randomSignature := stringutils.RandomString(20)
		err = jwtSigner.Verify(randomKey, randomMsg, randomSignature)

		if err == nil {
			t.Errorf("[%s-%s]Expect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})
}

func SharedTestRsaSignThenVerifyWithRandomInputsTest(t *testing.T, jwtSigner signer.Signer,
	priKey, pubKey, expectedErrMsg string) {
	randomMsg := stringutils.RandomString(50)

	t.Run("success", func(t *testing.T) {
		signature, err := jwtSigner.Sign(priKey, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(pubKey, randomMsg, signature)

		if err != nil {
			t.Errorf("[%s-%s]Cannot verify own signature, err got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}
	})

	t.Run("GIVEN_different-msg_WHEN_verify_THEN_return-err", func(t *testing.T) {
		randomMsg2 := stringutils.RandomString(20)
		signatureOfAnotherMsg, err := jwtSigner.Sign(priKey, randomMsg2)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(pubKey, randomMsg, signatureOfAnotherMsg)

		if err == nil {
			t.Errorf("[%s-%s]Expect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})

	t.Run("GIVEN_signature-of-another-key_WHEN_verify_THEN_return-err", func(t *testing.T) {
		signatureOfAnotherKey, err := jwtSigner.Sign(randomPkcs1PrivateKey, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		err = jwtSigner.Verify(pubKey, randomMsg, signatureOfAnotherKey)

		if err == nil {
			t.Errorf("[%s-%s]Expect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})

	t.Run("GIVEN_invalid-signature_WHEN_verify_THEN_return-err", func(t *testing.T) {
		_, err := jwtSigner.Sign(priKey, randomMsg)
		if err != nil {
			t.Errorf("[%s-%s]Expect err to be nil, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), err.Error())
		}

		randomSignature := stringutils.RandomString(20)
		err = jwtSigner.Verify(pubKey, randomMsg, randomSignature)

		if err == nil {
			t.Errorf("[%s-%s]Expect err, got nil", jwtSigner.Algo(), jwtSigner.SignScheme())
		}
		if err.Error() != expectedErrMsg {
			t.Errorf("[%s-%s]Expect err msg: %s, got: %s", jwtSigner.Algo(), jwtSigner.SignScheme(), expectedErrMsg, err.Error())
		}
	})
}
