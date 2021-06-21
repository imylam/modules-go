package stringutils

import (
	"strconv"
	"testing"
)

func TestRandomDigitString(t *testing.T) {
	var randDigits string
	for i := 1; i < 18; i++ {
		randDigits = RandomDigitString(i)
		stringLength := len(randDigits)

		if stringLength != i {
			t.Errorf("Expected string length: %d, got %d", i, stringLength)
		}
		if _, err := strconv.ParseInt(randDigits, 10, 64); err != nil {
			t.Errorf("Output is not numeric %s", randDigits)
		}
	}
}

func TestRandomString(t *testing.T) {
	var randString string
	for i := 1; i < 100; i++ {
		randString = RandomString(i)
		stringLength := len(randString)

		if stringLength != i {
			t.Errorf("Expected string length: %d, got %d", i, stringLength)
		}
	}
}

func TestIsEmail(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		email := "test@test.com"
		isEmail, _ := IsEmail(email)
		if !isEmail {
			t.Errorf("%s should not be a valid email", email)
		}
	})

	t.Run("GIVEN_invalid-email-1_WHEN_check-IsEmail_THEN_throw-err", func(t *testing.T) {
		email := "test@test"
		isEmail, _ := IsEmail(email)
		if isEmail {
			t.Errorf("%s should not be a valid email", email)
		}
	})

	t.Run("GIVEN_invalid-email-2_WHEN_check-IsEmail_THEN_throw-err", func(t *testing.T) {
		email := "testtest.co"
		isEmail, _ := IsEmail(email)
		if isEmail {
			t.Errorf("%s should not be a valid email", email)
		}
	})

	t.Run("GIVEN_invalid-email-3_WHEN_check-IsEmail_THEN_throw-err", func(t *testing.T) {
		email := "@test.com"
		isEmail, _ := IsEmail(email)
		if isEmail {
			t.Errorf("%s should not be a valid email", email)
		}
	})
}
