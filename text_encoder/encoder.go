package text_encoder

const (
	Base64RawStd = "Base64RawStdEncoding"
	Base64RawUrl = "Base64RawUrlEncoding"
	Base64Std    = "Base64StdEncoding"
	Hex          = "hexEncodeing"
	Utf8         = "utf-8"

	ErrorUnknownEncoding = "Unknow encoding"
)

type Encoder interface {
	Decode(string) ([]byte, error)
	Encode([]byte) string
}

// func New(encoding string) (Encoder, error) {
// 	switch encoding {
// 	case Base64RawStd:
// 		return &Base64RawStdEncoder{}, nil
// 	case Base64RawUrl:
// 		return &Base64RawUrlEncoder{}, nil
// 	case Base64Std:
// 		return &Base64StdEncoder{}, nil
// 	case Hex:
// 		return &HexEncoder{}, nil
// 	case Utf8:
// 		return &Utf8Encoder{}, nil
// 	default:
// 		return nil, errors.New("Unknow encoding")
// 	}
// }
