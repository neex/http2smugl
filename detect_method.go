package main

import (
	"bytes"
	"fmt"
	"net/url"
	"time"
)

type DetectRequestParams struct {
	AdditionalHeaders Headers
	Body              [][]byte
	BodyPartsDelay    time.Duration
	SkipBodyEndFlag   bool
}

type DetectMethod int

const (
	DetectContentLengthParsing DetectMethod = iota
	DetectChunkedBodyValidation
	DetectChunkedBodyConsumption
	DetectZeroBodyFragementInterruptsChunkedBody
)

var DetectMethods = []DetectMethod{
	DetectChunkedBodyConsumption,
	DetectChunkedBodyValidation,
	DetectContentLengthParsing,
	DetectZeroBodyFragementInterruptsChunkedBody,
}

func (d DetectMethod) GetRequests(
	sm SmugglingMethod,
	target *url.URL,
	smuggleVariant SmugglingVariant,
) (valid, invalid DetectRequestParams) {

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

		valid.Body = [][]byte{[]byte("0\r\n\r\n")}
		invalid.Body = [][]byte{[]byte("X\r\n\r\n")}

	case DetectChunkedBodyConsumption:
		valid.AdditionalHeaders = Headers{
			{"content-length", "5"},
			{"transfer-encoding", "chunked"},
		}
		sm.Smuggle(&valid.AdditionalHeaders[1], target, smuggleVariant)
		invalid.AdditionalHeaders = valid.AdditionalHeaders
		valid.Body = [][]byte{[]byte("0\r\n\r\n")}
		invalid.Body = [][]byte{[]byte("999\r\n")}

	case DetectZeroBodyFragementInterruptsChunkedBody:
		valid.Body = [][]byte{
			bytes.Repeat([]byte("a"), 65536),
			[]byte("x"),
		}
		invalid.Body = [][]byte{
			bytes.Repeat([]byte("a"), 65536),
			[]byte("x"),
		}
		valid.BodyPartsDelay = 1 * time.Second
		invalid.BodyPartsDelay = 1 * time.Second
		valid.SkipBodyEndFlag = true
		invalid.SkipBodyEndFlag = true

	default:
		panic(fmt.Errorf("unknown detect method: %#v", d))
	}
	return
}

func (d DetectMethod) AllowsSmugglingMethod(sm SmugglingMethod) bool {
	switch d {
	case DetectContentLengthParsing:
		return sm != HeaderSmugglingUnicodeCharacters
	case DetectZeroBodyFragementInterruptsChunkedBody:
		return sm == HeaderSmugglingNone
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
	case DetectZeroBodyFragementInterruptsChunkedBody:
		return "detect if zero body fragment interrupts chunked body"
	default:
		return "unknown detect method"
	}
}
