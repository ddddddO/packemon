package packemon

import (
	"bytes"
	"fmt"
	"strings"
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

func ParsedHTTPRequest(payload []byte) *HTTP {
	lineLength := bytes.Index(payload, []byte{0x0d, 0x0a}) // "\r\n"
	if lineLength == -1 {
		// TODO: こういうフォーマット不正みたいなパケットは、Dataをviewできた方がいいかも
		return nil
	}

	line := payload[0 : lineLength+1]
	split := bytes.Split(line, []byte{0x20}) // 半角スペース
	if len(split) >= 3 {
		http := &HTTP{
			Method:  string(split[0]),
			Uri:     string(split[1]),
			Version: string(split[2]),
		}

		hostLineLength := bytes.Index(payload[lineLength+2:], []byte{0x0d, 0x0a})
		if hostLineLength == -1 {
			return http
		}
		host := bytes.TrimPrefix(payload[lineLength+2:lineLength+2+hostLineLength], []byte{0x48, 0x6f, 0x73, 0x74, 0x3a}) // "Host:"
		http.Host = strings.TrimSpace(string(host))

		return http
	}

	return nil
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

type HTTPResponse struct {
	StatusLine string
	Header     string
	Body       string
}

func ParsedHTTPResponse(payload []byte) *HTTPResponse {
	lineLength := bytes.Index(payload, []byte{0x0d, 0x0a}) // "\r\n"

	line := payload[0 : lineLength+1]
	split := bytes.Split(line, []byte{0x20}) // 半角スペース
	if len(split) < 3 {
		return nil
	}

	return &HTTPResponse{
		StatusLine: fmt.Sprintf("%s %s %s", string(split[0]), string(split[1]), string(split[2])),
	}
}
