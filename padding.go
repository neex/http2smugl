package main

import (
	"fmt"
)

type PaddingMethod string

const (
	PaddingHeadersNone        PaddingMethod = "no padding headers"
	PaddingHeadersUnicodeSame               = "pad with same unicode header"
	PaddingHeadersASCIISame                 = "pad with same ASCII header"
)

var (
	PaddingMethods = []PaddingMethod{
		PaddingHeadersNone,

		// The other ones were working only in cloudflare bug
		// PaddingHeadersUnicodeSame,
		// PaddingHeadersASCIISame,
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

	case PaddingHeadersASCIISame:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{"header", "val"})
		}

	default:
		panic(fmt.Errorf("invalid padding header header: %#v", p))
	}

	return
}
