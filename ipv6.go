package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// rfc: https://datatracker.ietf.org/doc/html/rfc8200#page-6
// https://atmarkit.itmedia.co.jp/ait/articles/1201/05/news113.html
// ↑ によると、「TrafficClass」の前半4bitに拡張ヘッダ（Option）までの長さ入ってるっぽいけど
// https://datatracker.ietf.org/doc/html/rfc8200#section-4 によると、「NextHeader」の種類ごとに、拡張ヘッダー（Option）があるかどうかみたいなのがわかるっぽい？
// ちなみに、NextHeader は、IPv4 の Protocol と同じ値みたい
type IPv6 struct {
	Version       uint8 // 4bit
	TrafficClass  uint8
	FlowLabel     uint32 // 20bit
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	SrcAddr       []uint8
	DstAddr       []uint8

	Option []uint8

	Data []byte
}

func NewIPv6(protocol uint8, srcAddr []uint8, dstAddr []uint8) *IPv6 {
	return &IPv6{
		Version:       0x06,
		TrafficClass:  0x00,
		FlowLabel:     0x00000,
		PayloadLength: 0x0000,
		NextHeader:    protocol,
		HopLimit:      0x40,
		SrcAddr:       srcAddr,
		DstAddr:       dstAddr,
	}
}

func ParsedIPv6(payload []byte) *IPv6 {
	return &IPv6{
		Version:      payload[0] >> 4,
		TrafficClass: payload[0]<<4 | payload[1]>>4,
		FlowLabel:    uint32(payload[1]<<4>>4)<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
		// FlowLabel:    binary.BigEndian.Uint32(payload[1] << 4 | payload[2:4]),
		PayloadLength: binary.BigEndian.Uint16(payload[4:6]),
		NextHeader:    payload[6],
		HopLimit:      payload[7],
		SrcAddr:       payload[8:24],
		DstAddr:       payload[24:40],

		// TODO: 拡張ヘッダ付く場合あるため、それを除かないとダメ
		Data: payload[40:],
	}
}

// TODO: IPv4 と同じものは、IPv4_PROTO_HOGE 使っていいかも
const (
	IPv6_NEXT_HEADER_TCP    = IPv4_PROTO_TCP
	IPv6_NEXT_HEADER_UDP    = IPv4_PROTO_UDP
	IPv6_NEXT_HEADER_ICMPv6 = 0x3a
)

func (i *IPv6) StrSrcIPAddr() string {
	return uintsToStrIPv6Addr(i.SrcAddr)
}

func (i *IPv6) StrDstIPAddr() string {
	return uintsToStrIPv6Addr(i.DstAddr)
}

func uintsToStrIPv6Addr(byteAddr []uint8) string {
	ipv6Addr := net.IP(byteAddr)
	return ipv6Addr.To16().String()
}

func (i *IPv6) CalculatePayloadLength() {
	i.PayloadLength = uint16(len(i.Data))
}

func (i *IPv6) Bytes() []byte {
	buf := &bytes.Buffer{}

	buf.WriteByte(i.Version<<4 | i.TrafficClass>>4)
	buf.WriteByte(i.TrafficClass<<4 | uint8(i.FlowLabel>>16))                // FlowLabel の20bitから4bit取得
	WriteUint16(buf, uint16(i.FlowLabel&0b00000000000000001111111111111111)) // FlowLabel の20bitから4bitあたまはいらない
	WriteUint16(buf, i.PayloadLength)
	buf.WriteByte(i.NextHeader)
	buf.WriteByte(i.HopLimit)
	buf.Write(i.SrcAddr)
	buf.Write(i.DstAddr)
	buf.Write(i.Option)
	buf.Write(i.Data)

	return buf.Bytes()
}

// 上位レイヤのチェックサムを求めるための
// ref: https://datatracker.ietf.org/doc/html/rfc8200#section-8.1
func (i *IPv6) PseudoHeader(upperLayerLength uint32) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, i.SrcAddr)
	binary.Write(buf, binary.BigEndian, i.DstAddr)
	WriteUint32(buf, upperLayerLength)
	WriteUint32(buf, uint32(i.NextHeader))
	return buf.Bytes()
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (i *IPv6) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "IPv6",
		Children: []*FieldNode{
			{Name: "Version", Value: fmt.Sprintf("%d", i.Version)},
			{Name: "Traffic Class", Value: fmt.Sprintf("0x%02x", i.TrafficClass)},
			{Name: "Flow Label", Value: fmt.Sprintf("0x%05x", i.FlowLabel)},
			{Name: "Payload Length", Value: fmt.Sprintf("%d", i.PayloadLength)},
			{Name: "Next Header", Value: ipProtocolValueString(i.NextHeader)},
			{Name: "Hop Limit", Value: fmt.Sprintf("%d", i.HopLimit)},
			{Name: "Source Address", Value: i.StrSrcIPAddr()},
			{Name: "Destination Address", Value: i.StrDstIPAddr()},
		},
	}
}

// ScratchIPv6Assembler は、スクラッチ実装（IPv6.Bytes）による Assembler。
type ScratchIPv6Assembler struct{}

var _ Assembler = (*ScratchIPv6Assembler)(nil)

func (s *ScratchIPv6Assembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "version", Label: "Version", Kind: FieldKindHex, Default: "0x06"},
		{Key: "traffic_class", Label: "Traffic Class", Kind: FieldKindHex, Default: "0x00"},
		{Key: "flow_label", Label: "Flow Label", Kind: FieldKindHex, Default: "0x00000"},
		{Key: "payload_length", Label: "Payload Length", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_payload_length", Label: "Automatically calculate payload length ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "next_header", Label: "Next Header", Kind: FieldKindSelectOrHex, Default: "ICMPv6", Options: []string{"ICMPv6", "UDP", "TCP"}},
		{Key: "hop_limit", Label: "Hop Limit", Kind: FieldKindHex, Default: "0x40"},
		{Key: "src", Label: "Source IP Addr", Kind: FieldKindText, Default: "::1"},
		{Key: "dst", Label: "Destination IP Addr", Kind: FieldKindText, Default: "::1"},
	}
}

func (s *ScratchIPv6Assembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	ip, err := s.AssembleIPv6(values)
	if err != nil {
		return nil, err
	}
	ip.Data = payload

	// 自動計算のオン/オフ（オフにすれば「わざと不正な値」も送れる）
	if calc, err := boolFromValue(values["calc_payload_length"]); err != nil {
		return nil, fmt.Errorf("calc_payload_length: %w", err)
	} else if calc {
		ip.PayloadLength = uint16(len(payload))
	}

	return ip.Bytes(), nil
}

// AssembleIPv6 は values から IPv6 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、自動計算やL4連結はそちらの責務）へ
// 構造体を渡すために使う。
func (s *ScratchIPv6Assembler) AssembleIPv6(values map[string]any) (*IPv6, error) {
	ip := &IPv6{}
	var err error
	if ip.Version, err = uint8FromValue(values["version"]); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if ip.TrafficClass, err = uint8FromValue(values["traffic_class"]); err != nil {
		return nil, fmt.Errorf("traffic_class: %w", err)
	}
	if ip.FlowLabel, err = uint32FromValue(values["flow_label"]); err != nil {
		return nil, fmt.Errorf("flow_label: %w", err)
	}
	if ip.PayloadLength, err = uint16FromValue(values["payload_length"]); err != nil {
		return nil, fmt.Errorf("payload_length: %w", err)
	}
	if ip.NextHeader, err = ipProtocolFromValue(values["next_header"]); err != nil {
		return nil, fmt.Errorf("next_header: %w", err)
	}
	if ip.HopLimit, err = uint8FromValue(values["hop_limit"]); err != nil {
		return nil, fmt.Errorf("hop_limit: %w", err)
	}
	if ip.SrcAddr, err = ipv6AddrFromValue(values["src"]); err != nil {
		return nil, fmt.Errorf("src: %w", err)
	}
	if ip.DstAddr, err = ipv6AddrFromValue(values["dst"]); err != nil {
		return nil, fmt.Errorf("dst: %w", err)
	}
	return ip, nil
}
