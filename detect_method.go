package main

import "fmt"

type DetectRequestParams struct {
	Headers Headers
	Body    []byte
}

type DetectMethod int

const (
	DetectContentLengthParsing DetectMethod = iota
	DetectChunkedBodyValidation
	DetectChunkedBodyConsumption
)

var DetectMethods = []DetectMethod{
	DetectContentLengthParsing, DetectChunkedBodyValidation, DetectChunkedBodyConsumption,
}

func (d DetectMethod) GetRequests(sm SmugglingMethod, smuggleVariant SmugglingVariant) (valid, invalid DetectRequestParams) {
	switch d {
	case DetectContentLengthParsing:
		if sm == HeaderSmugglingNone {
			panic(fmt.Errorf("cannot use %#v with %#v", smuggleVariant, d))
		}
		valid.Headers = Headers{{"content-length", "1"}}
		invalid.Headers = Headers{{"content-length", "-1"}}
		sm.Smuggle(&valid.Headers[0], smuggleVariant)
		sm.Smuggle(&invalid.Headers[0], smuggleVariant)

	case DetectChunkedBodyValidation:
		valid.Headers = Headers{
			{"content-length", "5"},
			{"transfer-encoding", "chunked"},
		}
		sm.Smuggle(&valid.Headers[1], smuggleVariant)

		invalid.Headers = valid.Headers

		valid.Body = []byte("0\r\n\r\n")
		invalid.Body = []byte("X\r\n\r\n")

	case DetectChunkedBodyConsumption:
		valid.Headers = Headers{
			{"content-length", "5"},
			{"transfer-encoding", "chunked"},
		}
		sm.Smuggle(&valid.Headers[1], smuggleVariant)
		invalid.Headers = valid.Headers
		valid.Body = []byte("0\r\n\r\n")
		invalid.Body = []byte("999\r\n")

	default:
		panic(fmt.Errorf("unknown detect method: %#v", d))
	}
	return
}

func (d DetectMethod) AllowsSmugglingMethod(sm SmugglingMethod) bool {
	switch d {
	case DetectContentLengthParsing:
		return sm != HeaderSmugglingNone && sm != HeaderSmugglingUnicodeCharacters
	default:
		return true
	}
}

func (d DetectMethod) String() string {
	switch d {
	case DetectContentLengthParsing:
		return "detect content length parsing"
	case DetectChunkedBodyConsumption:
		return "detect chunked body consumption"
	case DetectChunkedBodyValidation:
		return "detect chunked body validation"
	default:
		return "unknown detect method"
	}
}
