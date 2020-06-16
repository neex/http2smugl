package main

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type RequestParams struct {
	target, method, connectAddr string
	headers                     Headers
	body                        []byte
	timeout                     time.Duration
}

func DoRequest(params *RequestParams) (Headers, []byte, error) {
	parsed, err := url.Parse(params.target)
	if err != nil {
		return nil, nil, err
	}

	if parsed.Scheme != "https" {
		return nil, nil, fmt.Errorf("scheme is %#v, but https is required", parsed.Scheme)
	}

	requestHeaders := Headers{
		{":authority", params.headers.GetDefault(":authority", parsed.Host)},
		{":method", params.headers.GetDefault(":method", params.method)},
		{":path", params.headers.GetDefault(":path", parsed.Path)},
		{":scheme", params.headers.GetDefault(":scheme", parsed.Scheme)},
		{"user-agent", params.headers.GetDefault("user-agent", "Mozilla/5.0")},
	}

	toSkip := map[string]struct{}{
		":authority": {},
		":method":    {},
		":path":      {},
		":scheme":    {},
		"user-agent": {},
	}

	for _, h := range params.headers {
		if _, ok := toSkip[h.Name]; ok {
			delete(toSkip, h.Name)
			continue
		}
		requestHeaders = append(requestHeaders, h)
	}

	targetAddr := params.connectAddr
	if targetAddr == "" {
		targetAddr = parsed.Host
	}

	return sendPreparedRequest(targetAddr, parsed.Host, prepareRequest(requestHeaders, params.body), params.timeout)
}

func prepareRequest(headers Headers, body []byte) []byte {
	hpackBuf := bytes.NewBuffer(nil)
	hpackEnc := hpack.NewEncoder(hpackBuf)
	for i := range headers {
		_ = hpackEnc.WriteField(hpack.HeaderField{
			Name:  headers[i].Name,
			Value: headers[i].Value,
		})
	}

	requestBuf := bytes.NewBuffer(nil)
	requestBuf.Write([]byte(http2.ClientPreface))

	framer := http2.NewFramer(requestBuf, nil)

	_ = framer.WriteSettings(http2.Setting{
		ID:  http2.SettingInitialWindowSize,
		Val: (1 << 31) - 1,
	})

	_ = framer.WriteWindowUpdate(0, (1<<31)-(1<<16)-1)

	_ = framer.WriteHeaders(http2.HeadersFrameParam{
		StreamID:      1,
		BlockFragment: hpackBuf.Bytes(),
		EndStream:     len(body) == 0,
		EndHeaders:    true,
	})

	start := 0
	for start < len(body) {
		end := start + 65536
		if end > len(body) {
			end = len(body)
		}
		_ = framer.WriteData(1, end == len(body), body[start:end])
		start = end
	}

	_ = framer.WriteSettingsAck()

	return requestBuf.Bytes()
}

func sendPreparedRequest(connectAddr, serverName string, request []byte, timeout time.Duration) (headers Headers, body []byte, err error) {
	address := connectAddr
	if _, _, err := net.SplitHostPort(connectAddr); err != nil {
		address = net.JoinHostPort(address, "443")
	}

	tcpConn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return nil, nil, err
	}

	defer func() { _ = tcpConn.Close() }()
	_ = tcpConn.SetDeadline(time.Now().Add(timeout))

	c := tls.Client(tcpConn, &tls.Config{
		NextProtos:         []string{"h2"},
		ServerName:         serverName,
		InsecureSkipVerify: true,
	})

	if _, err := c.Write(request); err != nil {
		return nil, nil, err
	}

	headersDecoder := hpack.NewDecoder(^uint32(0), func(f hpack.HeaderField) {
		headers = append(headers, Header{f.Name, f.Value})
	})

	framer := http2.NewFramer(nil, c)

	hasBody := false
	bodyRead := false
	headersDone := false
	for !headersDone || (hasBody && !bodyRead) {
		var f http2.Frame
		f, err = framer.ReadFrame()
		if err != nil {
			return
		}

		if f.Header().StreamID != 1 {
			continue
		}

		switch f := f.(type) {
		case *http2.HeadersFrame:
			if _, err := headersDecoder.Write(f.HeaderBlockFragment()); err != nil {
				return nil, nil, err
			}
			headersDone = f.HeadersEnded()
			hasBody = !f.StreamEnded()

		case *http2.ContinuationFrame:
			if _, err := headersDecoder.Write(f.HeaderBlockFragment()); err != nil {
				return nil, nil, err
			}
			headersDone = f.HeadersEnded()

		case *http2.DataFrame:
			// we should send window update, but who cares
			body = append(body, f.Data()...)
			bodyRead = f.StreamEnded()

		case *http2.RSTStreamFrame:
			err = fmt.Errorf("received RST frame: ErrCode=%v", f.ErrCode)
			return
		}

	}

	return
}
