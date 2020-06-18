package main

import (
	"bytes"
	"fmt"
	"sort"
)

type ResponseSet struct {
	statuses             map[string]struct{}
	minLength, maxLength int
}

func (rs *ResponseSet) AccountRequest(headers Headers, body []byte) {
	length := len(body)
	if rs.statuses == nil {
		rs.statuses = make(map[string]struct{})
		rs.minLength = length
		rs.maxLength = length
	}
	status, ok := headers.Get(":status")
	if !ok {
		status = "<error>"
	}
	rs.statuses[status] = struct{}{}
	if rs.minLength > length {
		rs.minLength = length
	}
	if rs.maxLength < length {
		rs.maxLength = length
	}
}

func (rs *ResponseSet) DistinguishableFrom(other *ResponseSet) bool {
	if rs.statuses == nil || other.statuses == nil {
		return true
	}
	statusSetsIntersect := false
	for k := range rs.statuses {
		if _, ok := other.statuses[k]; ok {
			statusSetsIntersect = true
			break
		}
	}
	if !statusSetsIntersect {
		return true
	}
	return rs.minLength > other.maxLength || rs.maxLength < other.minLength
}

func (rs *ResponseSet) String() string {
	buf := bytes.NewBuffer(nil)
	buf.WriteString("statuses ")
	var statuses []string
	for s := range rs.statuses {
		statuses = append(statuses, s)
	}
	sort.Strings(statuses)
	_, _ = fmt.Fprintf(buf, "%v, %v <= size <= %v", statuses, rs.minLength, rs.maxLength)
	return buf.String()
}
