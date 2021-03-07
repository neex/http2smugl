package main

import (
	"fmt"
)

type PaddingMethod int

const (
	PaddingHeadersNone PaddingMethod = iota
	PaddingHeadersASCIISame
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

	case PaddingHeadersASCIISame:
		for i := 0; i < PaddingHeaderCount; i++ {
			headers = append(headers, Header{"header", "val"})
		}

	default:
		panic(fmt.Errorf("invalid padding header header: %#v", p))
	}

	return
}

func (p PaddingMethod) String() string {
	switch p {
	case PaddingHeadersNone:
		return "no padding headers"
	case PaddingHeadersASCIISame:
		return "pad with same ASCII header"
	default:
		return "unknown padding method"
	}
}
