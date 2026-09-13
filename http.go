package packemon

import (
	"bytes"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const (
	PORT_HTTP  = 0x0050
	PORT_HTTPS = 0x01bb // 443
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
	Body       []byte

	len int
}

func (hr *HTTPResponse) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(hr.StatusLine)
	buf.Write(hr.Header.Bytes())
	buf.Write(hr.Body)
	return buf.Bytes()
}

type HTTPResponseHeader struct {
	Date          string
	ContentLength int
	ContentType   string
}

func (hrh *HTTPResponseHeader) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteString(hrh.Date)
	buf.WriteRune(rune(hrh.ContentLength))
	buf.WriteString(hrh.ContentType)
	return buf.Bytes()
}

// TODO: 多分このあたりバグってる。Monitor の http response の hexadecimal dump と Wireshark で異なる
// TODO: panic になることある
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
	body := b[len(b)-1][0:header.ContentLength]
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

// ScratchHTTPAssembler は、スクラッチ実装（HTTP.Bytes）による Assembler。
type ScratchHTTPAssembler struct{}

var _ Assembler = (*ScratchHTTPAssembler)(nil)

func (s *ScratchHTTPAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "method", Label: "Method", Kind: FieldKindText, Default: "GET"},
		{Key: "uri", Label: "Uri", Kind: FieldKindText, Default: "/"},
		{Key: "version", Label: "Version", Kind: FieldKindText, Default: "HTTP/1.1"},
		{Key: "host", Label: "Host", Kind: FieldKindText, Default: "github.com"},
		{Key: "user_agent", Label: "UserAgent", Kind: FieldKindText, Default: "packemon"},
		{Key: "accept", Label: "Accept", Kind: FieldKindText, Default: "*/*"},
	}
}

func (s *ScratchHTTPAssembler) Assemble(values map[string]any, _ []byte) ([]byte, error) {
	// HTTP はこのツールの扱いでは最上位レイヤのため payload は使わない
	http, err := s.AssembleHTTP(values)
	if err != nil {
		return nil, err
	}
	return http.Bytes(), nil
}

// AssembleHTTP は values から HTTP 構造体を組み立てる。
// TUI の動的フォームが、既存の送信経路（sender の packets）へ構造体を渡すために使う。
func (s *ScratchHTTPAssembler) AssembleHTTP(values map[string]any) (*HTTP, error) {
	http := &HTTP{}
	var err error
	if http.Method, err = stringFromValue(values["method"]); err != nil {
		return nil, fmt.Errorf("method: %w", err)
	}
	if http.Uri, err = stringFromValue(values["uri"]); err != nil {
		return nil, fmt.Errorf("uri: %w", err)
	}
	if http.Version, err = stringFromValue(values["version"]); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if http.Host, err = stringFromValue(values["host"]); err != nil {
		return nil, fmt.Errorf("host: %w", err)
	}
	if http.UserAgent, err = stringFromValue(values["user_agent"]); err != nil {
		return nil, fmt.Errorf("user_agent: %w", err)
	}
	if http.Accept, err = stringFromValue(values["accept"]); err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	return http, nil
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (h *HTTP) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "HTTP",
		Children: []*FieldNode{
			{Name: "Method", Value: h.Method},
			{Name: "Uri", Value: h.Uri},
			{Name: "Version", Value: h.Version},
			{Name: "Host", Value: h.Host},
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (hr *HTTPResponse) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "HTTP Response",
		Children: []*FieldNode{
			{Name: "Status Line", Value: hr.StatusLine},
		},
	}
}
