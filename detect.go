package main

import (
	"errors"
	"fmt"
	"log"
	"net/url"
	"time"
)

type DetectParams struct {
	Target        string
	RequestMethod string

	DetectMethod     DetectMethod
	SmugglingMethod  SmugglingMethod
	SmugglingVariant SmugglingVariant
	PaddingMethod    PaddingMethod
}

func (p *DetectParams) String() string {
	return fmt.Sprintf(
		"target=%s, http_method=%s, detect_method=%s, "+
			"smuggling_method=%s, smuggling_variant=%s, padding_method=%s",
		p.Target,
		p.RequestMethod,
		p.DetectMethod,
		p.SmugglingMethod,
		p.SmugglingVariant,
		p.PaddingMethod,
	)
}

type DetectResult int

const (
	Indistinguishable DetectResult = iota
	DistinguishableByTiming
	DistinguishableNotByTiming
)

func (r DetectResult) String() string {
	switch r {
	case Indistinguishable:
		return "indistinguishable"
	case DistinguishableByTiming:
		return "distinguishable by timing"
	case DistinguishableNotByTiming:
		return "distinguishable not by timing"
	default:
		return fmt.Sprintf("unknown result value: %#v", r)
	}
}

func Detect(params *DetectParams, connectTo string, timeout time.Duration, verbose bool) (DetectResult, error) {
	u, err := url.Parse(params.Target)
	if err != nil {
		return Indistinguishable, err
	}
	prefixHeaders := params.PaddingMethod.Headers()
	valid, invalid := params.DetectMethod.GetRequests(params.SmugglingMethod, u, params.SmugglingVariant)
	valid.AdditionalHeaders = prefixHeaders.Combine(valid.AdditionalHeaders)
	invalid.AdditionalHeaders = prefixHeaders.Combine(invalid.AdditionalHeaders)

	validResponses := &ResponseSet{}
	invalidResponses := &ResponseSet{}

	for i := 0; i < 14 && validResponses.DistinguishableFrom(invalidResponses); i++ {
		// The order is: V I ( V V V I I I ) x 4
		doValid := i == 0 || (i >= 2 && ((i-2)/3)%2 == 0)
		request := valid
		if !doValid {
			request = invalid
		}
		var (
			response  *HTTPMessage
			err       = errors.New("not started")
			triesLeft = 5
		)

		for err != nil && triesLeft > 0 {
			triesLeft--
			response, err = DoRequest(&RequestParams{
				Target:      u,
				Method:      params.RequestMethod,
				ConnectAddr: connectTo,
				Headers:     request.AdditionalHeaders,
				Body:        request.Body,
				Timeout:     timeout,
			})
		}

		if err != nil {
			_, ok := err.(RSTError)
			if !ok {
				log.Printf("request: %v, error: %v", params, err)
			}
		}

		if doValid {
			validResponses.AccountResponse(response)
		} else {
			invalidResponses.AccountResponse(response)
		}
	}

	result := Indistinguishable
	if validResponses.DistinguishableFrom(invalidResponses) {
		if validResponses.AllResponsesAreErrors() || invalidResponses.AllResponsesAreErrors() {
			result = DistinguishableByTiming // TODO: this is not accurate
		} else {
			result = DistinguishableNotByTiming
		}
	}

	if verbose {
		log.Printf("%s: valid=%s, invalid=%s, result=%v",
			params, validResponses, invalidResponses, result)
	}
	return result, nil
}
