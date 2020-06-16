package main

import (
	"errors"
	"fmt"
	"log"
	"time"
)

type DetectParams struct {
	Target           string
	DetectMethod     DetectMethod
	SmuggleMethod    SmugglingMethod
	SmugglingVariant interface{}
	PaddingMethod    PaddingMethod
	RequestMethod    string
}

func (p *DetectParams) String() string {
	return fmt.Sprintf("%#v", p) // TODO
}

func Detect(params *DetectParams, connectTo string, timeout time.Duration, verbose bool) (bool, error) {
	prefixHeaders := params.PaddingMethod.Headers()
	valid, invalid := params.DetectMethod.GetHeaders(params.SmuggleMethod, params.SmugglingVariant)
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
				target:      params.Target,
				method:      params.RequestMethod,
				connectAddr: connectTo,
				headers:     request.Headers,
				body:        request.Body,
				timeout:     timeout,
			})

			if err != nil && verbose {
				log.Printf("request error: %s, valid=%v: %v", params, doValid, err)
			}
		}

		if doValid {
			validResponses.AccountRequest(headers, body)
		} else {
			invalidResponses.AccountRequest(headers, body)
		}
	}

	distinguishable := validResponses.DistinguishableFrom(invalidResponses)
	if verbose {
		log.Printf("%s: valid=%s, invalid=%s, distinguishable=%v",
			params, validResponses, invalidResponses, distinguishable)
	}
	return distinguishable, nil
}
