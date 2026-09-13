package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// https://www.infraexpert.com/study/tcpip1.html
type IPv4 struct {
	Version        uint8  // 4bit
	Ihl            uint8  // 4bit. hearder length
	Tos            uint8  // 8bit. type of service
	TotalLength    uint16 // 16bit. total length
	Identification uint16 // 16bit
	Flags          uint8  // 3bit
	FragmentOffset uint16 // 13bit
	Ttl            uint8  // 8bit
	Protocol       uint8  // 8bit
	HeaderChecksum uint16 // 16bit
	SrcAddr        uint32 // 32bit
	DstAddr        uint32 // 32bit

	Options []uint8
	Padding []uint8

	Data []byte
}

func NewIPv4(protocol uint8, srcAddr uint32, dstAddr uint32) *IPv4 {
	return &IPv4{
		Version:        0x04,
		Ihl:            0x05,
		Tos:            0x00,
		TotalLength:    0x54,
		Identification: 0x0d94,
		Flags:          0x40,
		FragmentOffset: 0x0,
		Ttl:            0x40,
		Protocol:       protocol,
		HeaderChecksum: 0,
		SrcAddr:        srcAddr,
		DstAddr:        dstAddr,
	}
}

const (
	IPv4_PROTO_ICMP uint8 = 0x01
	IPv4_PROTO_TCP  uint8 = 0x06
	IPv4_PROTO_UDP  uint8 = 0x11
)

var IPv4Protocols = map[uint8]string{
	IPv4_PROTO_ICMP: "ICMP",
	IPv4_PROTO_TCP:  "TCP",
	IPv4_PROTO_UDP:  "UDP",
}

func ParsedIPv4(payload []byte) *IPv4 {
	return &IPv4{
		Version:        payload[0] >> 4,
		Ihl:            payload[0],
		Tos:            payload[1],
		TotalLength:    binary.BigEndian.Uint16(payload[2:4]),
		Identification: binary.BigEndian.Uint16(payload[4:6]),
		Flags:          payload[6] & 0b11100000,
		FragmentOffset: 0b0001111111111111 & binary.BigEndian.Uint16(payload[6:8]),
		Ttl:            payload[8],
		Protocol:       payload[9],
		HeaderChecksum: binary.BigEndian.Uint16(payload[10:12]),
		SrcAddr:        binary.BigEndian.Uint32(payload[12:16]),
		DstAddr:        binary.BigEndian.Uint32(payload[16:20]),

		Data: payload[20:],
	}
}

func (i *IPv4) CalculateTotalLength() {
	headerLength := 20 + len(i.Options) + len(i.Padding)
	i.TotalLength = uint16(headerLength) + uint16(len(i.Data))
}

// TODO: ここだけではないけど要refactor
func (i *IPv4) CalculateChecksum() {
	header := make([]byte, 20)
	header = append(header, i.Version<<4|i.Ihl)
	header = append(header, i.Tos)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.TotalLength)
	header = append(header, b...)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.Identification)
	header = append(header, b...)
	header = append(header, i.Flags)

	b = make([]byte, 2)
	// TODO: FragmentOffset/Ttl のフィールド追加するときこのあたり要確認
	binary.BigEndian.PutUint16(b, i.FragmentOffset|uint16(i.Ttl))
	header = append(header, b...)

	header = append(header, i.Protocol)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.HeaderChecksum)
	header = append(header, b...)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.SrcAddr)
	header = append(header, b...)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.DstAddr)
	header = append(header, b...)

	i.HeaderChecksum = binary.BigEndian.Uint16(calculateChecksum(header))
}

func (i *IPv4) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.WriteByte(i.Version<<4 | i.Ihl)
	buf.WriteByte(i.Tos)
	WriteUint16(buf, i.TotalLength)
	WriteUint16(buf, i.Identification)
	WriteUint16(buf, hton(uint16(i.Flags)|i.FragmentOffset))
	buf.WriteByte(i.Ttl)
	buf.WriteByte(i.Protocol)
	WriteUint16(buf, i.HeaderChecksum)
	WriteUint32(buf, i.SrcAddr)
	WriteUint32(buf, i.DstAddr)
	buf.Write(i.Data)

	return buf.Bytes()
}

func (i *IPv4) StrSrcIPAddr() string {
	return uint32ToStrIPv4Addr(i.SrcAddr)
}

func (i *IPv4) StrDstIPAddr() string {
	return uint32ToStrIPv4Addr(i.DstAddr)
}

func uint32ToStrIPv4Addr(byteAddr uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, byteAddr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}

// uint32ToIPv4Str は uint32 表現の IPv4 アドレスを "192.168.0.1" 形式へ変換する。
func uint32ToIPv4Str(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d", byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr))
}

// uint32ToIPv4Bytes は uint32 表現の IPv4 アドレスを 4 バイト列（ビッグエンディアン）へ変換する。
func uint32ToIPv4Bytes(addr uint32) []byte {
	return []byte{byte(addr >> 24), byte(addr >> 16), byte(addr >> 8), byte(addr)}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (i *IPv4) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "IPv4",
		Children: []*FieldNode{
			{Name: "Version", Value: fmt.Sprintf("%d", i.Version)},
			{Name: "Header Length", Value: fmt.Sprintf("%d", i.Ihl)},
			{Name: "Type of Service", Value: fmt.Sprintf("0x%02x", i.Tos)},
			{Name: "Total Length", Value: fmt.Sprintf("%d", i.TotalLength)},
			{Name: "Identification", Value: fmt.Sprintf("0x%04x", i.Identification)},
			{Name: "Flags", Value: fmt.Sprintf("0x%02x", i.Flags)},
			{Name: "Fragment Offset", Value: fmt.Sprintf("%d", i.FragmentOffset)},
			{Name: "TTL", Value: fmt.Sprintf("%d", i.Ttl)},
			{Name: "Protocol", Value: ipProtocolValueString(i.Protocol)},
			{Name: "Header Checksum", Value: fmt.Sprintf("0x%04x", i.HeaderChecksum)},
			{Name: "Source Address", Value: i.StrSrcIPAddr()},
			{Name: "Destination Address", Value: i.StrDstIPAddr()},
		},
	}
}

// ScratchIPv4Assembler は、スクラッチ実装（IPv4.Bytes）による Assembler。
type ScratchIPv4Assembler struct{}

var _ Assembler = (*ScratchIPv4Assembler)(nil)

func (s *ScratchIPv4Assembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "version", Label: "Version", Kind: FieldKindHex, Default: "0x04"},
		{Key: "ihl", Label: "Header Length", Kind: FieldKindHex, Default: "0x05"},
		{Key: "tos", Label: "Type of Service", Kind: FieldKindHex, Default: "0x00"},
		{Key: "total_length", Label: "Total Length", Kind: FieldKindHex, Default: "0x0014"},
		{Key: "calc_total_length", Label: "Automatically calculate total length ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "identification", Label: "Identification", Kind: FieldKindHex, Default: "0xe31f"},
		{Key: "flags", Label: "Flags", Kind: FieldKindHex, Default: "0x40"},
		{Key: "fragment_offset", Label: "Fragment Offset", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "ttl", Label: "TTL", Kind: FieldKindHex, Default: "0x80"},
		{Key: "protocol", Label: "Protocol", Kind: FieldKindSelectOrHex, Default: "ICMP", Options: []string{"ICMP", "UDP", "TCP"}},
		{Key: "checksum", Label: "Header Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "calc_checksum", Label: "Automatically calculate checksum ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "src", Label: "Source IP Addr", Kind: FieldKindText, Default: "0.0.0.0"},
		{Key: "dst", Label: "Destination IP Addr", Kind: FieldKindText, Default: "0.0.0.0"},
	}
}

func (s *ScratchIPv4Assembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	ip, err := s.AssembleIPv4(values)
	if err != nil {
		return nil, err
	}
	ip.Data = payload

	// 自動計算のオン/オフ（オフにすれば「わざと不正な値」も送れる）
	if calc, err := boolFromValue(values["calc_total_length"]); err != nil {
		return nil, fmt.Errorf("calc_total_length: %w", err)
	} else if calc {
		ip.CalculateTotalLength()
	}
	if calc, err := boolFromValue(values["calc_checksum"]); err != nil {
		return nil, fmt.Errorf("calc_checksum: %w", err)
	} else if calc {
		ip.HeaderChecksum = 0x0
		ip.CalculateChecksum()
	}

	return ip.Bytes(), nil
}

// AssembleIPv4 は values から IPv4 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、自動計算やL4連結はそちらの責務）へ
// 構造体を渡すために使う。
func (s *ScratchIPv4Assembler) AssembleIPv4(values map[string]any) (*IPv4, error) {
	ip := &IPv4{}
	var err error
	if ip.Version, err = uint8FromValue(values["version"]); err != nil {
		return nil, fmt.Errorf("version: %w", err)
	}
	if ip.Ihl, err = uint8FromValue(values["ihl"]); err != nil {
		return nil, fmt.Errorf("ihl: %w", err)
	}
	if ip.Tos, err = uint8FromValue(values["tos"]); err != nil {
		return nil, fmt.Errorf("tos: %w", err)
	}
	if ip.TotalLength, err = uint16FromValue(values["total_length"]); err != nil {
		return nil, fmt.Errorf("total_length: %w", err)
	}
	if ip.Identification, err = uint16FromValue(values["identification"]); err != nil {
		return nil, fmt.Errorf("identification: %w", err)
	}
	if ip.Flags, err = uint8FromValue(values["flags"]); err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}
	if ip.FragmentOffset, err = uint16FromValue(values["fragment_offset"]); err != nil {
		return nil, fmt.Errorf("fragment_offset: %w", err)
	}
	if ip.Ttl, err = uint8FromValue(values["ttl"]); err != nil {
		return nil, fmt.Errorf("ttl: %w", err)
	}
	if ip.Protocol, err = ipProtocolFromValue(values["protocol"]); err != nil {
		return nil, fmt.Errorf("protocol: %w", err)
	}
	if ip.HeaderChecksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if ip.SrcAddr, err = ipv4AddrFromValue(values["src"]); err != nil {
		return nil, fmt.Errorf("src: %w", err)
	}
	if ip.DstAddr, err = ipv4AddrFromValue(values["dst"]); err != nil {
		return nil, fmt.Errorf("dst: %w", err)
	}
	return ip, nil
}

// ipProtocolFromValue は、プロトコル名（"ICMP" 等。TUI の選択肢）、"0x01" 等の文字列、
// または uint8 そのものを受け付ける。
func ipProtocolFromValue(v any) (uint8, error) {
	if s, ok := v.(string); ok {
		switch s {
		case "ICMP":
			return IPv4_PROTO_ICMP, nil
		case "UDP":
			return IPv4_PROTO_UDP, nil
		case "TCP":
			return IPv4_PROTO_TCP, nil
		case "ICMPv6":
			return IPv6_NEXT_HEADER_ICMPv6, nil
		}
	}
	return uint8FromValue(v)
}

// ipProtocolValueString は、プロトコル番号を「%#x (名称)」形式で返す（名称が不明なら %#x のみ）。
func ipProtocolValueString(protocol uint8) string {
	if name, ok := IPv4Protocols[protocol]; ok {
		return fmt.Sprintf("%#x (%s)", protocol, name)
	}
	return fmt.Sprintf("%#x", protocol)
}
