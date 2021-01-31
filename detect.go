package main

import (
	"errors"
	"fmt"
	"log"
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

type DetectResult bool

const (
	Indistinguishable DetectResult = false
	Distinguishable   DetectResult = true
)

func (r DetectResult) String() string {
	switch r {
	case Distinguishable:
		return "distinguishable"
	case Indistinguishable:
		return "indistinguishable"
	default:
		return fmt.Sprintf("unknown result value: %#v", r)
	}
}

func Detect(params *DetectParams, connectTo string, timeout time.Duration, verbose bool) (DetectResult, error) {
	prefixHeaders := params.PaddingMethod.Headers()
	valid, invalid := params.DetectMethod.GetRequests(params.SmugglingMethod, params.SmugglingVariant)
	valid.Headers = prefixHeaders.Combine(valid.Headers)
	invalid.Headers = prefixHeaders.Combine(invalid.Headers)

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
			headers   Headers
			body      []byte
			err       = errors.New("not started")
			triesLeft = 5
		)

		for err != nil && triesLeft > 0 {
			triesLeft--
			headers, body, err = DoRequest(&RequestParams{
				Target:      params.Target,
				Method:      params.RequestMethod,
				ConnectAddr: connectTo,
				Headers:     request.Headers,
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
			validResponses.AccountRequest(headers, body)
		} else {
			invalidResponses.AccountRequest(headers, body)
		}
	}

	var result DetectResult
	if validResponses.DistinguishableFrom(invalidResponses) {
		result = Distinguishable
	} else {
		result = Indistinguishable
	}
	if verbose {
		log.Printf("%s: valid=%s, invalid=%s, result=%v",
			params, validResponses, invalidResponses, result)
	}
	return result, nil
}
