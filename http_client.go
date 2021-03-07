package main

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/http2"
)

type RequestParams struct {
	Target              *url.URL
	Method, ConnectAddr string
	Headers             Headers
	NoAutoHeaders       bool
	Body                []byte
	Timeout             time.Duration
	AddContentLength    bool
}

type HTTPMessage struct {
	Headers Headers
	Body    []byte
}

type RSTError struct {
	Code http2.ErrCode
}

func (r RSTError) Error() string {
	return fmt.Sprintf("received RST frame, code=%v", r.Code)
}

func DoRequest(params *RequestParams) (*HTTPMessage, error) {
	var proto string

	switch params.Target.Scheme {
	case "https", "https+http2":
		proto = "http2"
	case "https+h3":
		proto = "http3"
	default:
		return nil, fmt.Errorf(`invalid scheme: %#v`, params.Target.Scheme)
	}

	var headers Headers

	if params.NoAutoHeaders {
		headers = params.Headers
	} else {
		headers = Headers{
			{":authority", params.Target.Host},
			{":method", params.Method},
			{":path", params.Target.Path},
			{":scheme", "https"},
			{"user-agent", "Mozilla/5.0"},
		}

		toSkip := make(map[string]struct{})
		for i := range headers {
			h := &headers[i]
			if v, ok := params.Headers.Get(h.Name); ok {
				h.Value = v
				toSkip[h.Name] = struct{}{}
			}
		}

		for _, h := range params.Headers {
			if _, ok := toSkip[h.Name]; ok {
				delete(toSkip, h.Name)
				continue
			}
			headers = append(headers, h)
		}
	}

	if params.AddContentLength {
		headers = append(headers, Header{"content-length", strconv.Itoa(len(params.Body))})
	}

	targetAddr := params.ConnectAddr
	if targetAddr == "" {
		targetAddr = params.Target.Host
	}

	switch proto {
	case "http2":
		return sendHTTP2Request(targetAddr, params.Target.Host, false, &HTTPMessage{headers, params.Body}, params.Timeout)
	case "http3":
		return sendHTTP3Request(targetAddr, params.Target.Host, false, &HTTPMessage{headers, params.Body}, params.Timeout)
	default:
		panic(fmt.Errorf("invalid proto: %#v", proto))
	}
}
