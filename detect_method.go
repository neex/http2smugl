package main

import "fmt"

type DetectRequestParams struct {
	Headers Headers
	Body    []byte
}

type DetectMethod string

const (
	DetectContentLengthParsing    = "detect content length parsing"
	DetectTransferEncodingParsing = "detect transfer encoding parsing"
	DetectChunkedBodyConsumption  = "detect chunked body consumption"
	DetectChunkedBodyValidation   = "detect chunked body validation"
)

var DetectMethods = []DetectMethod{
	DetectContentLengthParsing, DetectTransferEncodingParsing, DetectChunkedBodyValidation, DetectChunkedBodyConsumption,
}

func (d DetectMethod) GetHeaders(sm SmugglingMethod, smuggleVariant interface{}) (valid, invalid DetectRequestParams) {
	switch d {
	case DetectContentLengthParsing:
		if sm == HeaderSmugglingNone {
			panic(fmt.Errorf("cannot use %#v with %#v", smuggleVariant, d))
		}
		valid.Headers = Headers{{"content-length", "0"}}
		invalid.Headers = Headers{{"content-length", "-1"}}
		sm.Smuggle(&valid.Headers[0], smuggleVariant)
		sm.Smuggle(&invalid.Headers[0], smuggleVariant)

	case DetectTransferEncodingParsing:
		if sm == HeaderSmugglingNone {
			panic(fmt.Errorf("cannot use %#v with %#v", smuggleVariant, d))
		}
		valid.Headers = Headers{{"transfer-encoding", "chunked"}}
		invalid.Headers = Headers{{"transfer-encoding", "pizda"}}
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
	if sm != HeaderSmugglingNone {
		return true
	}
	return d == DetectChunkedBodyConsumption || d == DetectChunkedBodyValidation
}
