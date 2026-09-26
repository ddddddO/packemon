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

// https://www.infraexpert.com/study/tcpip4.html
// https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
type ICMPv4EchoOrEchoReply struct {
	Header     *ICMPHeader
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

const (
	ICMPv4_TYPE_ECHO_MESSAGE            = 0x08
	ICMPv4_TYPE_ECHO_REPLY_MESSAGE      = 0x00
	ICMPv4_TYPE_DESTINATION_UNREACHABLE = 0x03
)

func ParsedICMPv4(payload []byte) *ICMPv4EchoOrEchoReply {
	return &ICMPv4EchoOrEchoReply{
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

// icmp request
func NewICMPv4() *ICMPv4EchoOrEchoReply {
	icmpv4 := &ICMPv4EchoOrEchoReply{
		Header: &ICMPHeader{
			Typ:  ICMPv4_TYPE_ECHO_MESSAGE,
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
func (*ICMPv4EchoOrEchoReply) TimestampForTypeTimestampRequest() []byte {
	originalTimestamp := time.Now().Unix()
	receiveTimestamp := 0x00000000
	transmitTimestamp := 0x00000000

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(originalTimestamp))
	bb := binary.LittleEndian.AppendUint32(b, uint32(receiveTimestamp))
	return binary.LittleEndian.AppendUint32(bb, uint32(transmitTimestamp))
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func (i *ICMPv4EchoOrEchoReply) CalculateChecksum() {
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

func (i *ICMPv4EchoOrEchoReply) Bytes() []byte {
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
func (i *ICMPv4EchoOrEchoReply) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "ICMPv4",
		Children: []*FieldNode{
			{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Header.Typ)},
			{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Header.Code)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Header.Checksum)},
			{Name: "Identifier", Value: fmt.Sprintf("0x%04x", i.Identifier)},
			{Name: "Sequence", Value: fmt.Sprintf("0x%04x", i.Sequence)},
		},
	}
}

// ScratchICMPv4Assembler は、スクラッチ実装（ICMPv4.Bytes）による Assembler。
type ScratchICMPv4Assembler struct{}

var _ Assembler = (*ScratchICMPv4Assembler)(nil)

func (s *ScratchICMPv4Assembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "type", Label: "Type", Kind: FieldKindHex, Default: "0x08"},
		{Key: "code", Label: "Code", Kind: FieldKindHex, Default: "0x00"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "identifier", Label: "Identifier", Kind: FieldKindHex, Default: "0x34a1"},
		{Key: "sequence", Label: "Sequence", Kind: FieldKindHex, Default: "0x0001"},
	}
}

func (s *ScratchICMPv4Assembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	icmpv4, err := s.AssembleICMPv4(values)
	if err != nil {
		return nil, err
	}
	icmpv4.Data = payload

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
func (s *ScratchICMPv4Assembler) AssembleICMPv4(values map[string]any) (*ICMPv4EchoOrEchoReply, error) {
	icmpv4 := &ICMPv4EchoOrEchoReply{Header: &ICMPHeader{}}
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
	return icmpv4, nil
}
