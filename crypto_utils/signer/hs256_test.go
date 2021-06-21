package signer

import (
	"fmt"
	"strings"
	"testing"

	"github.com/imylam/modules-go/stringutils"
)

var (
	testKey       = "i am a secret key"
	testMsg       = "I am a plain text"
	testSignature = "776c4dbecfb74a9cab47e559bbe8ede3cbe9892433765ea371af64f11fcc9a0a"

	signer = SignerHS256{}
)

func TestAlgo(t *testing.T) {
	algo := signer.Algo()

	if algo != "HS256" {
		t.Errorf("Expect algo to be: %s, got: %s", "HS256", algo)
	}
}

func TestSignAgainstStandard(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		signature, err := signer.Sign(testKey, testMsg)

		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}
		if signature != testSignature {
			t.Errorf("Expect signature: %s, got: %s", testSignature, signature)
		}
	})
}

func TestVerifyAgainstStandard(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		err := signer.Verify(testKey, testMsg, testSignature)

		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}
	})
}

func TestSignThenVerifyWithRandomInputs(t *testing.T) {

	randomKey := stringutils.RandomString(20)
	randomMsg := stringutils.RandomString(50)

	t.Run("success", func(t *testing.T) {
		signature, err := signer.Sign(randomKey, randomMsg)
		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}

		err = signer.Verify(randomKey, randomMsg, signature)

		if err != nil {
			t.Errorf("Cannot verify own signature, err got: %s", err.Error())
		}
	})

	t.Run("GIVEN_different-msg_WHEN_verify_THEN_return-err", func(t *testing.T) {
		randomMsg2 := stringutils.RandomString(20)
		signatureOfAnotherMsg, err := signer.Sign(randomKey, randomMsg2)
		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}

		err = signer.Verify(randomKey, randomMsg, signatureOfAnotherMsg)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if err.Error() != ERR_INVALID_SIGNATURE {
			t.Errorf("Expect err msg: %s, got: %s", ERR_INVALID_SIGNATURE, err.Error())
		}
	})

	t.Run("GIVEN_signature-of-another-key_WHEN_verify_THEN_return-err", func(t *testing.T) {
		randomKey2 := stringutils.RandomString(20)
		signatureOfAnotherKey, err := signer.Sign(randomKey2, randomMsg)
		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}

		err = signer.Verify(randomKey, randomMsg, signatureOfAnotherKey)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if err.Error() != ERR_INVALID_SIGNATURE {
			t.Errorf("Expect err msg: %s, got: %s", ERR_INVALID_SIGNATURE, err.Error())
		}
	})

	t.Run("GIVEN_invalid-signature_WHEN_verify_THEN_return-err", func(t *testing.T) {
		_, err := signer.Sign(randomKey, randomMsg)
		if err != nil {
			t.Errorf("Expect err to be nil, got: %s", err.Error())
		}

		err = signer.Verify(randomKey, randomMsg, testSignature)

		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if err.Error() != ERR_INVALID_SIGNATURE {
			t.Errorf("Expect err msg: %s, got: %s", ERR_INVALID_SIGNATURE, err.Error())
		}
	})
}

func TestVerify(t *testing.T) {
	t.Run("GIVEN_wrongly-encoded-signature_WHEN_sign_THEN_return-err", func(t *testing.T) {
		expectedErrMsg := "failed to decode signature: encoding/hex:"
		utf8Signature := stringutils.RandomString(20)

		err := signer.Verify(testKey, testMsg, utf8Signature)

		fmt.Print(err.Error())
		if err == nil {
			t.Errorf("Expect err, got nil")
		}
		if !strings.Contains(err.Error(), expectedErrMsg) {
			t.Errorf("Expect err msg: %s, got: %s", expectedErrMsg, err.Error())
		}
	})
}
