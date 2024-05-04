package main

import (
	"bytes"
	"fmt"
)

type http struct {
	method    string
	uri       string
	version   string
	host      string
	userAgent string
	accept    string

	body string
}

func newHTTP() *http {
	return &http{
		method:    "GET",
		uri:       "/",
		version:   "HTTP/1.1",
		host:      "tools.m-bsys.com",
		userAgent: "packemon",
		accept:    "*/*",
	}
}

func (h *http) toBytes() []byte {
	var buf bytes.Buffer
	line := fmt.Sprintf("%s %s %s\r\n", h.method, h.uri, h.version)
	buf.WriteString(line)
	buf.WriteString(fmt.Sprintf("Host: %s\r\n", h.host))
	buf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", h.userAgent))
	buf.WriteString(fmt.Sprintf("Accept: %s\r\n", h.accept))
	buf.WriteString("\r\n")
	return buf.Bytes()
}
