package packemon

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const (
	PORT_HTTP = 0x0050
)

type HTTP struct {
	Method        string
	Uri           string
	Version       string
	Host          string
	UserAgent     string
	Accept        string
	ContentLength string

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
		Host:      "192.168.10.110",
		UserAgent: "packemon/0.0.1",
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
	Header     *HTTPResponseHeader
	Body       string

	len int
}

type HTTPResponseHeader struct {
	Date          string
	ContentLength int
	ContentType   string
}

func ParsedHTTPResponse(payload []byte) *HTTPResponse {
	sep := []byte{0x0d, 0x0a} // "\r\n"

	statusLine := ""
	header := &HTTPResponseHeader{}
	length := bytes.Count(payload, sep) * 2
	split := bytes.Split(payload, sep)
	for i, s := range split {
		// ここでやると、recievedで確保した余分な要素分入ってくる
		// length += len(s)

		if i == 0 {
			statusLine = string(s)
			length += len(s)
			continue
		}
		if bytes.Contains(s, []byte("Date: ")) {
			length += len(s)
			header.Date = string(bytes.TrimPrefix(s, []byte("Date: ")))
			continue
		}
		if bytes.Contains(s, []byte("Content-Length: ")) {
			length += len(s)

			var err error
			header.ContentLength, err = strconv.Atoi(string(bytes.TrimPrefix(s, []byte("Content-Length: "))))
			if err != nil {
				log.Printf("failed to Atoi: %s\n", err)
			}
			continue
		}
		if bytes.Contains(s, []byte("Content-Type: ")) {
			length += len(s)
			header.ContentType = string(bytes.TrimPrefix(s, []byte("Content-Type: ")))
			continue
		}

		// log.Printf("not suported header: %s, len: %d\n", string(s), len(bytes.TrimSpace(s)))
	}
	b := bytes.SplitAfter(payload, append(sep, sep...))
	body := string(b[len(b)-1][0:header.ContentLength])
	length += header.ContentLength

	return &HTTPResponse{
		StatusLine: statusLine,
		Header:     header,
		Body:       body,

		len: length,
	}
}

func (h *HTTPResponse) Len() int {
	return h.len
}
