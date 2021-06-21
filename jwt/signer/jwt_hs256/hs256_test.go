package jwt_hs256

import (
	"testing"

	"github.com/imylam/modules-go/jwt/signer"
	"github.com/imylam/modules-go/jwt/signer/hmac"
)

var (
	testKey       = "i am a secret key"
	testSignature = "d2xNvs-3SpyrR-VZu-jt48vpiSQzdl6jca9k8R_Mmgo"

	jwtSigner = JwtHS256{}
)

func TestAlgo(t *testing.T) {
	signer.SharedTestAlgo(t, &jwtSigner, ALGO)
}

func TestSignScheme(t *testing.T) {
	signer.SharedTestSignScheme(t, &jwtSigner, ALGO)
}

func TestSignAgainstStandard(t *testing.T) {
	signer.SharedTestSignAgainstReference(t, &jwtSigner, testKey, testSignature)

	// t.Run("success", func(t *testing.T) {
	// 	signature, err := jwtSigner.Sign(testKey, testMsg)

	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}
	// 	if signature != testSignature {
	// 		t.Errorf("Expect signature: %s, got: %s", testSignature, signature)
	// 	}
	// })
}

func TestVerifyAgainstStandard(t *testing.T) {
	signer.SharedTestVerifyAgainstReference(t, &jwtSigner, testKey, testSignature)

	// t.Run("success", func(t *testing.T) {
	// 	err := jwtSigner.Verify(testKey, testMsg, testSignature)

	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}
	// })
}

func TestSignThenVerifyWithRandomInputs(t *testing.T) {
	signer.SharedTestHmacSignThenVerifyWithRandomInputsTest(t, &jwtSigner, hmac.ERR_INVALID_SIGNATURE)
	// randomKey := stringutils.RandomString(20)
	// randomMsg := stringutils.RandomString(50)

	// t.Run("success", func(t *testing.T) {
	// 	signature, err := jwtSigner.Sign(randomKey, randomMsg)
	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}

	// 	err = jwtSigner.Verify(randomKey, randomMsg, signature)

	// 	if err != nil {
	// 		t.Errorf("Cannot verify own signature, err got: %s", err.Error())
	// 	}
	// })

	// t.Run("GIVEN_different-msg_WHEN_verify_THEN_return-err", func(t *testing.T) {
	// 	randomMsg2 := stringutils.RandomString(20)
	// 	signatureOfAnotherMsg, err := jwtSigner.Sign(randomKey, randomMsg2)
	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}

	// 	err = jwtSigner.Verify(randomKey, randomMsg, signatureOfAnotherMsg)

	// 	if err == nil {
	// 		t.Errorf("Expect err, got nil")
	// 	}
	// 	if err.Error() != hmac.ERR_INVALID_SIGNATURE {
	// 		t.Errorf("Expect err msg: %s, got: %s", hmac.ERR_INVALID_SIGNATURE, err.Error())
	// 	}
	// })

	// t.Run("GIVEN_signature-of-another-key_WHEN_verify_THEN_return-err", func(t *testing.T) {
	// 	randomKey2 := stringutils.RandomString(20)
	// 	signatureOfAnotherKey, err := jwtSigner.Sign(randomKey2, randomMsg)
	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}

	// 	err = jwtSigner.Verify(randomKey, randomMsg, signatureOfAnotherKey)

	// 	if err == nil {
	// 		t.Errorf("Expect err, got nil")
	// 	}
	// 	if err.Error() != hmac.ERR_INVALID_SIGNATURE {
	// 		t.Errorf("Expect err msg: %s, got: %s", hmac.ERR_INVALID_SIGNATURE, err.Error())
	// 	}
	// })

	// t.Run("GIVEN_invalid-signature_WHEN_verify_THEN_return-err", func(t *testing.T) {
	// 	_, err := jwtSigner.Sign(randomKey, randomMsg)
	// 	if err != nil {
	// 		t.Errorf("Expect err to be nil, got: %s", err.Error())
	// 	}

	// 	err = jwtSigner.Verify(randomKey, randomMsg, testSignature)

	// 	if err == nil {
	// 		t.Errorf("Expect err, got nil")
	// 	}
	// 	if err.Error() != hmac.ERR_INVALID_SIGNATURE {
	// 		t.Errorf("Expect err msg: %s, got: %s", hmac.ERR_INVALID_SIGNATURE, err.Error())
	// 	}
	// })
}
