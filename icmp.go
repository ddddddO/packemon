package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// https://ja.wikipedia.org/wiki/Internet_Control_Message_Protocol

// ICMPv4,v6 で共通のヘッダー
type ICMPHeader struct {
	Typ      uint8
	Code     uint8
	Checksum uint16
}

// Echo / Echo Reply
// Timestamp / Timestamp Reply
// Information Request / Information Reply
// Address Mask Request / Address Mask Reply
type ICMPv4Echo struct {
	Header     *ICMPHeader
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

// Destination Unreachable / Time Exceeded / Source Quench
type ICMPv4Error struct {
	Header     *ICMPHeader
	Unused     uint32
	OriginalIP *IPv4

	// memo: Echo or Echo Reply 以外の送信で DestinationUnreachable が返ってくるパターンがあれば以下の型指定はダメなので、型を指定するのではなく↑のIPv4のデータ部をパース処理するところに委ねる
	// OriginalICMP *ICMPv4EchoOrEchoReply
}

// Parameter Problem
type ICMPv4ParameterProblem struct {
	Header     *ICMPHeader
	Pointer    uint8
	Unused     [3]byte
	OriginalIP *IPv4
}

// Redirect
type ICMPv4Redirect struct {
	Header         *ICMPHeader
	GatewayAddress uint32
	OriginalIP     *IPv4
}

const (
	ICMPv4_TYPE_ECHO                    = 0x08
	ICMPv4_TYPE_ECHO_REPLY              = 0x00
	ICMPv4_TYPE_DESTINATION_UNREACHABLE = 0x03
	ICMPv4_TYPE_SOURCE_QUENCH           = 0x04
	ICMPv4_TYPE_REDIRECT                = 0x05
	ICMPv4_TYPE_ROUTER_ADVERTISEMENT    = 0x09
	ICMPv4_TYPE_ROUTER_SOLICITATION     = 0x0a
	ICMPv4_TYPE_TIME_EXCEEDED           = 0x0b
	ICMPv4_TYPE_PARAMETER_PROBLEM       = 0x0c
	ICMPv4_TYPE_TIMESTAMP               = 0x0d
	ICMPv4_TYPE_TIMESTAMP_REPLY         = 0x0e
	ICMPv4_TYPE_INFORMATION_REQUEST     = 0x0f
	ICMPv4_TYPE_INFORMATION_REPLY       = 0x10
	ICMPv4_TYPE_ADDRESS_MASK_REQUEST    = 0x11
	ICMPv4_TYPE_ADDRESS_MASK_REPLY      = 0x12
)

func ParsedICMPv4Echo(payload []byte) *ICMPv4Echo {
	return &ICMPv4Echo{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Identifier: binary.BigEndian.Uint16(payload[4:6]),
		Sequence:   binary.BigEndian.Uint16(payload[6:8]),
		Data:       payload[8:],
	}
}

func ParsedICMPv4Error(payload []byte) *ICMPv4Error {
	return &ICMPv4Error{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Unused:     binary.BigEndian.Uint32(payload[4:8]),
		OriginalIP: ParsedIPv4(payload[8:]),
	}
}

func ParsedICMPv4ParameterProblem(payload []byte) *ICMPv4ParameterProblem {
	return &ICMPv4ParameterProblem{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		Pointer:    payload[4],
		Unused:     [3]byte(payload[5:8]),
		OriginalIP: ParsedIPv4(payload[8:]),
	}
}

func ParsedICMPv4Redirect(payload []byte) *ICMPv4Redirect {
	return &ICMPv4Redirect{
		Header: &ICMPHeader{
			Typ:      payload[0],
			Code:     payload[1],
			Checksum: binary.BigEndian.Uint16(payload[2:4]),
		},
		GatewayAddress: binary.BigEndian.Uint32(payload[4:8]),
		OriginalIP:     ParsedIPv4(payload[8:]),
	}
}

func NewICMPv4Echo() *ICMPv4Echo {
	icmpv4 := &ICMPv4Echo{
		Header: &ICMPHeader{
			Typ:  ICMPv4_TYPE_ECHO,
			Code: 0,
		},
		Identifier: 0x34a1,
		Sequence:   0x0001,
	}

	// pingのecho requestのpacketを観察すると以下で良さそう
	// タイムスタンプ要求以外で必要ではないよう
	// icmpv4.Data = icmpv4.TimestampForTypeTimestampRequest()

	icmpv4.CalculateChecksum()

	return icmpv4
}

// icmpのタイムスタンプ要求で必要みたい
// Linuxで、sudo hping3 1.1.1.1 --icmp --icmptype 13 でタイムスタンプ要求のパケット確認できる
func (*ICMPv4Echo) TimestampForTypeTimestampRequest() []byte {
	originalTimestamp := time.Now().Unix()
	receiveTimestamp := 0x00000000
	transmitTimestamp := 0x00000000

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(originalTimestamp))
	bb := binary.LittleEndian.AppendUint32(b, uint32(receiveTimestamp))
	return binary.LittleEndian.AppendUint32(bb, uint32(transmitTimestamp))
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func (i *ICMPv4Echo) CalculateChecksum() {
	b := i.Bytes()
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16

	ret := make([]byte, 2)
	binary.LittleEndian.PutUint16(ret, ^uint16(s))
	i.Header.Checksum = binary.BigEndian.Uint16(ret)
}

func (i *ICMPv4Echo) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint16(buf, i.Identifier)
	WriteUint16(buf, i.Sequence)
	buf.Write(i.Data)
	return buf.Bytes()
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (i *ICMPv4Echo) FieldNode() *FieldNode {
	children := []*FieldNode{
		{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
		{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
		{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
		{Name: "Identifier", Value: fmt.Sprintf("0x%04x", i.Identifier)},
		{Name: "Sequence", Value: fmt.Sprintf("0x%04x", i.Sequence)},
	}
	if len(i.Data) > 0 {
		children = append(children, &FieldNode{Name: "Data", Value: fmt.Sprintf("0x%x", i.Data)})
	}

	return &FieldNode{
		Name:     "ICMPv4",
		Children: children,
	}
}

func (i *ICMPv4Error) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.Unused)
	buf.Write(i.OriginalIP.Bytes())
	return buf.Bytes()
}

func (i *ICMPv4Error) FieldNode() *FieldNode {
	node := &FieldNode{
		Name: "ICMPv4",
		Children: []*FieldNode{
			{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
			{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
			{Name: "Unused", Value: fmt.Sprintf("0x%x", i.Unused)},
		},
	}

	// 例えば、Echo Message -> Destination Unreachable が返ってきた時の Echo Messageの内容とそのIPパケットがOriginalに入ってくる
	original := &FieldNode{
		Name: "Original",
	}
	if i.OriginalIP != nil {
		original.Children = append(original.Children, i.OriginalIP.FieldNode())
	}
	originalICMP := originalICMPv4FieldNode(i.OriginalIP)
	if originalICMP != nil {
		original.Children = append(original.Children, originalICMP)
	}

	if len(original.Children) > 0 {
		node.Children = append(node.Children, original)
	}
	return node
}

func originalICMPv4FieldNode(ipv4 *IPv4) *FieldNode {
	if len(ipv4.Data) > 0 {
		switch ipv4.Data[0] {
		case
			ICMPv4_TYPE_ECHO, ICMPv4_TYPE_ECHO_REPLY,
			ICMPv4_TYPE_TIMESTAMP, ICMPv4_TYPE_TIMESTAMP_REPLY,
			ICMPv4_TYPE_INFORMATION_REQUEST, ICMPv4_TYPE_INFORMATION_REPLY,
			ICMPv4_TYPE_ADDRESS_MASK_REQUEST, ICMPv4_TYPE_ADDRESS_MASK_REPLY:

			parsed := ParsedICMPv4Echo(ipv4.Data)
			return parsed.FieldNode()
		case ICMPv4_TYPE_DESTINATION_UNREACHABLE, ICMPv4_TYPE_TIME_EXCEEDED, ICMPv4_TYPE_SOURCE_QUENCH:
			parsed := ParsedICMPv4Error(ipv4.Data)
			return parsed.FieldNode()
		case ICMPv4_TYPE_PARAMETER_PROBLEM:
			parsed := ParsedICMPv4ParameterProblem(ipv4.Data)
			return parsed.FieldNode()
		case ICMPv4_TYPE_REDIRECT:
			parsed := ParsedICMPv4Redirect(ipv4.Data)
			return parsed.FieldNode()
		}
	}
	return nil
}

func (i *ICMPv4ParameterProblem) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	buf.WriteByte(i.Pointer)
	buf.Write(i.Unused[:])
	buf.Write(i.OriginalIP.Bytes())
	return buf.Bytes()
}

func (i *ICMPv4ParameterProblem) FieldNode() *FieldNode {
	node := &FieldNode{
		Name: "ICMPv4",
		Children: []*FieldNode{
			{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
			{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
			{Name: "Pointer", Value: fmt.Sprintf("0x%02x", i.Pointer)},
			{Name: "Unused", Value: fmt.Sprintf("0x%x", i.Unused)},
		},
	}

	original := &FieldNode{
		Name: "Original",
	}
	if i.OriginalIP != nil {
		original.Children = append(original.Children, i.OriginalIP.FieldNode())
	}
	originalICMP := originalICMPv4FieldNode(i.OriginalIP)
	if originalICMP != nil {
		original.Children = append(original.Children, originalICMP)
	}

	if len(original.Children) > 0 {
		node.Children = append(node.Children, original)
	}
	return node
}

func (i *ICMPv4Redirect) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Header.Typ)
	buf.WriteByte(i.Header.Code)
	WriteUint16(buf, i.Header.Checksum)
	WriteUint32(buf, i.GatewayAddress)
	buf.Write(i.OriginalIP.Bytes())
	return buf.Bytes()
}

func (i *ICMPv4Redirect) FieldNode() *FieldNode {
	node := &FieldNode{
		Name: "ICMPv4",
		Children: []*FieldNode{
			{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
			{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
			{Name: "Gateway Address", Value: fmt.Sprintf("0x%x", i.GatewayAddress)},
		},
	}

	original := &FieldNode{
		Name: "Original",
	}
	if i.OriginalIP != nil {
		original.Children = append(original.Children, i.OriginalIP.FieldNode())
	}
	originalICMP := originalICMPv4FieldNode(i.OriginalIP)
	if originalICMP != nil {
		original.Children = append(original.Children, originalICMP)
	}

	if len(original.Children) > 0 {
		node.Children = append(node.Children, original)
	}
	return node
}

// ScratchICMPv4EchoAssembler は、スクラッチ実装（ICMPv4Echo.Bytes）による Assembler。
type ScratchICMPv4EchoAssembler struct{}

var _ Assembler = (*ScratchICMPv4EchoAssembler)(nil)

func (s *ScratchICMPv4EchoAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "type", Label: "Type", Kind: FieldKindHex, Default: "0x08"},
		{Key: "code", Label: "Code", Kind: FieldKindHex, Default: "0x00"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "identifier", Label: "Identifier", Kind: FieldKindHex, Default: "0x34a1"},
		{Key: "sequence", Label: "Sequence", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "data", Label: "Data", Kind: FieldKindHex, Default: ""},
	}
}

func (s *ScratchICMPv4EchoAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	icmpv4, err := s.AssembleICMPv4(values)
	if err != nil {
		return nil, err
	}
	// データ部に任意入力できるようにしたためコメントアウト
	// icmpv4.Data = payload

	// 自動計算のオン/オフ（オフにすれば「わざと不正な値」も送れる）
	if calc, err := boolFromValue(values["calc_checksum"]); err != nil {
		return nil, fmt.Errorf("calc_checksum: %w", err)
	} else if calc {
		icmpv4.Header.Checksum = 0x0
		icmpv4.CalculateChecksum()
	}

	return icmpv4.Bytes(), nil
}

// AssembleICMPv4 は values から ICMPv4 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、自動計算やL3連結はそちらの責務）へ
// 構造体を渡すために使う。
func (s *ScratchICMPv4EchoAssembler) AssembleICMPv4(values map[string]any) (*ICMPv4Echo, error) {
	icmpv4 := &ICMPv4Echo{Header: &ICMPHeader{}}
	var err error
	if icmpv4.Header.Typ, err = uint8FromValue(values["type"]); err != nil {
		return nil, fmt.Errorf("type: %w", err)
	}
	if icmpv4.Header.Code, err = uint8FromValue(values["code"]); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}
	if icmpv4.Header.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if icmpv4.Identifier, err = uint16FromValue(values["identifier"]); err != nil {
		return nil, fmt.Errorf("identifier: %w", err)
	}
	if icmpv4.Sequence, err = uint16FromValue(values["sequence"]); err != nil {
		return nil, fmt.Errorf("sequence: %w", err)
	}
	if icmpv4.Data, err = bytesFromValue(values["data"]); err != nil {
		return nil, fmt.Errorf("data: %w", err)
	}
	return icmpv4, nil
}
