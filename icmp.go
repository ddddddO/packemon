package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"
)

// https://www.infraexpert.com/study/tcpip4.html
// https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
type ICMP struct {
	Typ        uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	Sequence   uint16
	Data       []byte
}

const (
	ICMP_TYPE_REQUEST = 0x08
)

func ParsedICMP(payload []byte) *ICMP {
	return &ICMP{
		Typ:        payload[0],
		Code:       payload[1],
		Checksum:   binary.BigEndian.Uint16(payload[2:4]),
		Identifier: binary.BigEndian.Uint16(payload[4:6]),
		Sequence:   binary.BigEndian.Uint16(payload[6:8]),
		Data:       payload[8:],
	}
}

// icmp request
func NewICMP() *ICMP {
	icmp := &ICMP{
		Typ:        ICMP_TYPE_REQUEST,
		Code:       0,
		Identifier: 0x34a1,
		Sequence:   0x0001,
	}

	// pingのecho requestのpacketを観察すると以下で良さそう
	// タイムスタンプ要求以外で必要ではないよう
	// icmp.Data = icmp.TimestampForTypeTimestampRequest()

	icmp.CalculateChecksum()

	return icmp
}

// icmpのタイムスタンプ要求で必要みたい
// Linuxで、sudo hping3 1.1.1.1 --icmp --icmptype 13 でタイムスタンプ要求のパケット確認できる
func (*ICMP) TimestampForTypeTimestampRequest() []byte {
	originalTimestamp := time.Now().Unix()
	receiveTimestamp := 0x00000000
	transmitTimestamp := 0x00000000

	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(originalTimestamp))
	bb := binary.LittleEndian.AppendUint32(b, uint32(receiveTimestamp))
	return binary.LittleEndian.AppendUint32(bb, uint32(transmitTimestamp))
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func (i *ICMP) CalculateChecksum() {
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
	i.Checksum = binary.BigEndian.Uint16(ret)
}

func (i *ICMP) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Typ)
	buf.WriteByte(i.Code)
	WriteUint16(buf, i.Checksum)
	WriteUint16(buf, i.Identifier)
	WriteUint16(buf, i.Sequence)
	buf.Write(i.Data)
	return buf.Bytes()
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (i *ICMP) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "ICMP",
		Children: []*FieldNode{
			{Name: "Type", Value: fmt.Sprintf("0x%02x", i.Typ)},
			{Name: "Code", Value: fmt.Sprintf("0x%02x", i.Code)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", i.Checksum)},
			{Name: "Identifier", Value: fmt.Sprintf("0x%04x", i.Identifier)},
			{Name: "Sequence", Value: fmt.Sprintf("0x%04x", i.Sequence)},
		},
	}
}

// ScratchICMPAssembler は、スクラッチ実装（ICMP.Bytes）による Assembler。
type ScratchICMPAssembler struct{}

var _ Assembler = (*ScratchICMPAssembler)(nil)

func (s *ScratchICMPAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "type", Label: "Type", Kind: FieldKindHex, Default: "0x08"},
		{Key: "code", Label: "Code", Kind: FieldKindHex, Default: "0x00"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "identifier", Label: "Identifier", Kind: FieldKindHex, Default: "0x34a1"},
		{Key: "sequence", Label: "Sequence", Kind: FieldKindHex, Default: "0x0001"},
	}
}

func (s *ScratchICMPAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	icmp, err := s.AssembleICMP(values)
	if err != nil {
		return nil, err
	}
	icmp.Data = payload

	// 自動計算のオン/オフ（オフにすれば「わざと不正な値」も送れる）
	if calc, err := boolFromValue(values["calc_checksum"]); err != nil {
		return nil, fmt.Errorf("calc_checksum: %w", err)
	} else if calc {
		icmp.Checksum = 0x0
		icmp.CalculateChecksum()
	}

	return icmp.Bytes(), nil
}

// AssembleICMP は values から ICMP 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、自動計算やL3連結はそちらの責務）へ
// 構造体を渡すために使う。
func (s *ScratchICMPAssembler) AssembleICMP(values map[string]any) (*ICMP, error) {
	icmp := &ICMP{}
	var err error
	if icmp.Typ, err = uint8FromValue(values["type"]); err != nil {
		return nil, fmt.Errorf("type: %w", err)
	}
	if icmp.Code, err = uint8FromValue(values["code"]); err != nil {
		return nil, fmt.Errorf("code: %w", err)
	}
	if icmp.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if icmp.Identifier, err = uint16FromValue(values["identifier"]); err != nil {
		return nil, fmt.Errorf("identifier: %w", err)
	}
	if icmp.Sequence, err = uint16FromValue(values["sequence"]); err != nil {
		return nil, fmt.Errorf("sequence: %w", err)
	}
	return icmp, nil
}
