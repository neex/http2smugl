package main

import (
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type RequestParams struct {
	Target              *url.URL
	Method, ConnectAddr string
	Headers             Headers
	NoAutoHeaders       bool
	NoUserAgent         bool
	Body                [][]byte
	Timeout             time.Duration
	AddContentLength    bool
	BodyPartsDelay      time.Duration
	SkipBodyEndFlag     bool
}

type HTTPMessage struct {
	Headers Headers
	Body    [][]byte
}

type ConnDropError struct {
	Wrapped error
}

func (r ConnDropError) Error() string {
	return fmt.Sprintf("server dropped connection, error=%v", r.Wrapped)
}

type TimeoutError struct {
}

func (t TimeoutError) Error() string {
	return "timeout"
}

func (t TimeoutError) Timeout() bool {
	return true
}

func (t TimeoutError) Temporary() bool {
	return false
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
		if params.Target.Path == "" {
			params.Target.Path = "/"
		}
		headers = Headers{
			{":authority", params.Target.Host},
			{":method", params.Method},
			{":path", params.Target.Path},
			{":scheme", "https"},
		}

		if !params.NoUserAgent {
			headers = append(headers, Header{"user-agent", "Mozilla/5.0"})
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
		totalLength := 0
		for _, body := range params.Body {
			totalLength += len(body)
		}
		headers = append(headers, Header{"content-length", strconv.Itoa(totalLength)})
	}

	targetAddr := params.ConnectAddr
	if targetAddr == "" {
		targetAddr = params.Target.Host
	}

	switch proto {
	case "http2":
		return sendHTTP2Request(targetAddr,
			params.Target.Host,
			false,
			&HTTPMessage{headers, params.Body},
			params.Timeout,
			params.BodyPartsDelay,
			params.SkipBodyEndFlag)

	case "http3":
		return sendHTTP3Request(targetAddr,
			params.Target.Host,
			&HTTPMessage{headers, params.Body},
			params.Timeout,
			params.BodyPartsDelay,
			params.SkipBodyEndFlag)
	default:
		panic(fmt.Errorf("invalid proto: %#v", proto))
	}
}
