package main

import (
	"fmt"
	"net/url"
)

type DetectRequestParams struct {
	AdditionalHeaders Headers
	Body              []byte
}

type DetectMethod int

const (
	DetectContentLengthParsing DetectMethod = iota
	DetectChunkedBodyValidation
	DetectChunkedBodyConsumption
)

var DetectMethods = []DetectMethod{
	DetectChunkedBodyConsumption,
	DetectChunkedBodyValidation,
	DetectContentLengthParsing,
}

func (d DetectMethod) GetRequests(sm SmugglingMethod, target *url.URL, smuggleVariant SmugglingVariant) (valid, invalid DetectRequestParams) {
	switch d {
	case DetectContentLengthParsing:
		valid.AdditionalHeaders = Headers{{"content-length", "1"}}
		invalid.AdditionalHeaders = Headers{{"content-length", "-1"}}
		sm.Smuggle(&valid.AdditionalHeaders[0], target, smuggleVariant)
		sm.Smuggle(&invalid.AdditionalHeaders[0], target, smuggleVariant)

	case DetectChunkedBodyValidation:
		valid.AdditionalHeaders = Headers{
			{"content-length", "5"},
			{"transfer-encoding", "chunked"},
		}
		sm.Smuggle(&valid.AdditionalHeaders[1], target, smuggleVariant)

		invalid.AdditionalHeaders = valid.AdditionalHeaders

		valid.Body = []byte("0\r\n\r\n")
		invalid.Body = []byte("X\r\n\r\n")

	case DetectChunkedBodyConsumption:
		valid.AdditionalHeaders = Headers{
			{"content-length", "5"},
			{"transfer-encoding", "chunked"},
		}
		sm.Smuggle(&valid.AdditionalHeaders[1], target, smuggleVariant)
		invalid.AdditionalHeaders = valid.AdditionalHeaders
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
		return sm != HeaderSmugglingUnicodeCharacters
	default:
		return sm != HeaderSmugglingNewlineLongerValue
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
