package main

import (
	"fmt"
	"strconv"
)

type PaddingMethod string

const (
	PaddingHeadersNone             PaddingMethod = "no padding headers"
	PaddingHeadersUnicodeSame                    = "pad with same unicode header"
	PaddingHeadersUnicodeDifferent               = "pad with different unicode headers"
	PaddingHeadersASCIISame                      = "pad with same ASCII header"
	PaddingHeadersASCIIDifferent                 = "pad with different ASCII header"
	PaddingHeadersCookie                         = "pad with cookie header"
)

var (
	PaddingMethods = []PaddingMethod{
		PaddingHeadersNone,
		PaddingHeadersUnicodeSame,
		PaddingHeadersUnicodeDifferent,
		PaddingHeadersASCIISame,
		PaddingHeadersASCIIDifferent,
		PaddingHeadersCookie,
	}
	PaddingHeaderCount = 100
)

func (p PaddingMethod) Headers() (headers Headers) {
	switch p {
	case PaddingHeadersNone:
		// No headers

	case PaddingHeadersUnicodeSame:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{`¯\_(ツ)_/¯`, "val"})
		}

	case PaddingHeadersUnicodeDifferent:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{`¯\_(ツ)_/¯` + strconv.Itoa(i), "val"})
		}

	case PaddingHeadersASCIISame:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{"header", "val"})
		}

	case PaddingHeadersASCIIDifferent:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{"header" + strconv.Itoa(i), "val"})
		}

	case PaddingHeadersCookie:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{"cookie", fmt.Sprintf("cook_%v=value", i)})
		}

	default:
		panic(fmt.Errorf("invalid padding header header: %#v", p))
	}

	return
}
