package main

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type RequestParams struct {
	Target              *url.URL
	Method, ConnectAddr string
	Headers             Headers
	NoAutoHeaders       bool
	NoUserAgent         bool
	Body                []byte
	Timeout             time.Duration
	AddContentLength    bool
}

type HTTPMessage struct {
	Headers Headers
	Body    []byte
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

func DoRequest(params *RequestParams) (string, *HTTPMessage, error) {
	var proto string

	switch params.Target.Scheme {
	case "https", "https+http2":
		proto = "http2"
	case "https+h3":
		proto = "http3"
	default:
		return "",nil, fmt.Errorf(`invalid scheme: %#v`, params.Target.Scheme)
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
		}

		if !params.NoUserAgent {
			headers = append(headers, Header{"user-agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36"})
		}

		toSkip := make(map[string]struct{})
		for i := range headers {
			h := &headers[i]
			if v, ok := params.Headers.Get(h.Name); ok {
				if h.Name == ":method" && strings.HasPrefix(v,"METHOD") {
					v = strings.Replace(v,"METHOD", params.Method,1)
				}
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
