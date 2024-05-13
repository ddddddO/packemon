package packemon

import (
	"bytes"
	"fmt"
)

const (
	PORT_HTTP = 0x0050
)

type HTTP struct {
	Method    string
	Uri       string
	Version   string
	Host      string
	UserAgent string
	Accept    string

	Body string
}

func NewHTTP() *HTTP {
	return &HTTP{
		Method:    "GET",
		Uri:       "/",
		Version:   "HTTP/1.1",
		Host:      "tools.m-bsys.com",
		UserAgent: "packemon",
		Accept:    "*/*",
	}
}

func (h *HTTP) Bytes() []byte {
	buf := &bytes.Buffer{}
	line := fmt.Sprintf("%s %s %s\r\n", h.Method, h.Uri, h.Version)
	buf.WriteString(line)
	buf.WriteString(fmt.Sprintf("Host: %s\r\n", h.Host))
	buf.WriteString(fmt.Sprintf("User-Agent: %s\r\n", h.UserAgent))
	buf.WriteString(fmt.Sprintf("Accept: %s\r\n", h.Accept))
	buf.WriteString("\r\n")
	return buf.Bytes()
}
