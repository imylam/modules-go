package signer

type Signer interface {
	Algo() string
	SignScheme() string
	Sign(string, string) (string, error)
	Verify(string, string, string) error
}
