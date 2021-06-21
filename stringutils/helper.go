package stringutils

import (
	"math/rand"
	"regexp"
	"time"
)

const (
	digitset   = "0123456789"
	charset    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	regexEmail = `^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)`
)

var (
	seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))
)

// RandomDigitString generates a random digit only string with given length
func RandomDigitString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = digitset[seededRand.Intn(len(digitset))]
	}
	return string(b)
}

// RandomString generates a random string with given length
func RandomString(length int) string {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return string(b)
}

// IsEmail checks if a give string is in email format
func IsEmail(testString string) (bool, error) {
	match, err := regexp.MatchString(regexEmail, testString)
	if err != nil {
		return false, err
	}

	return match, nil
}
