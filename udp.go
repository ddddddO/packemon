package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type UDP struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16 // TODO: 後で計算用メソッドを。そもそも他のヘッダのchecksumと同じ計算っぽいから、独立させるかも
	Data     []byte
}

func ParsedUDP(payload []byte) *UDP {
	return &UDP{
		SrcPort:  binary.BigEndian.Uint16(payload[0:2]),
		DstPort:  binary.BigEndian.Uint16(payload[2:4]),
		Length:   binary.BigEndian.Uint16(payload[4:6]),
		Checksum: binary.BigEndian.Uint16(payload[6:8]),
		Data:     payload[8:],
	}
}

func (u *UDP) Len() {
	length := 0
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.SrcPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.DstPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.Length)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.Checksum)
	length += len(b)

	length += len(u.Data)
	u.Length = uint16(length)
}

func (u *UDP) CalculateChecksum(ipv4 *IPv4) {
	pseudoHeaderIPv4 := func() []byte {
		buf := &bytes.Buffer{}
		binary.Write(buf, binary.BigEndian, ipv4.SrcAddr)
		binary.Write(buf, binary.BigEndian, ipv4.DstAddr)
		buf.WriteByte(0x00)
		buf.WriteByte(ipv4.Protocol)
		u.Len()
		WriteUint16(buf, u.Length)
		return buf.Bytes()
	}

	forUDPChecksum := &bytes.Buffer{}
	forUDPChecksum.Write(pseudoHeaderIPv4())
	forUDPChecksum.Write(u.Bytes())
	if len(u.Data)%2 != 0 {
		forUDPChecksum.WriteByte(0x00)
	}

	data := forUDPChecksum.Bytes()
	u.Checksum = binary.BigEndian.Uint16(calculateChecksum(data))
}

// IPv6 ではチェックサムがないため、上のレイヤでチェックサムが必要なため
func (u *UDP) CalculateChecksumForIPv6(ipv6 *IPv6) {
	pseudoHeader := ipv6.PseudoHeader(uint32(u.Length))
	forUDPChecksum := &bytes.Buffer{}
	forUDPChecksum.Write(pseudoHeader)
	forUDPChecksum.Write(u.Bytes())
	if len(u.Data)%2 != 0 {
		forUDPChecksum.WriteByte(0x00)
	}

	data := forUDPChecksum.Bytes()
	u.Checksum = binary.BigEndian.Uint16(calculateChecksum(data))
}

func (u *UDP) Bytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, u.SrcPort)
	WriteUint16(buf, u.DstPort)
	WriteUint16(buf, u.Length)
	WriteUint16(buf, u.Checksum)
	buf.Write(u.Data)
	return buf.Bytes()
}

func createUDPAddr(ipBytes []byte, port uint16) (*net.UDPAddr, error) {
	if len(ipBytes) != net.IPv4len && len(ipBytes) != net.IPv6len {
		return nil, fmt.Errorf("invalid IP addr length: %d bytes", len(ipBytes))
	}

	return &net.UDPAddr{
		IP:   net.IP(ipBytes),
		Port: int(port),
	}, nil
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (u *UDP) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "UDP",
		Children: []*FieldNode{
			{Name: "Source Port", Value: fmt.Sprintf("%#x (%d)", u.SrcPort, u.SrcPort)},
			{Name: "Destination Port", Value: fmt.Sprintf("%#x (%d)", u.DstPort, u.DstPort)},
			{Name: "Length", Value: fmt.Sprintf("%d", u.Length)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", u.Checksum)},
		},
	}
}

// ScratchUDPAssembler は、スクラッチ実装（UDP.Bytes）による Assembler。
type ScratchUDPAssembler struct{}

var _ Assembler = (*ScratchUDPAssembler)(nil)

func (s *ScratchUDPAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "src_port", Label: "Source Port", Kind: FieldKindText, Default: "47000"},
		{Key: "dst_port", Label: "Destination Port", Kind: FieldKindText, Default: "53"},
		{Key: "length", Label: "Length", Kind: FieldKindHex, Default: "0x0030"},
		{Key: "calc_length", Label: "Automatically calculate length ?", Kind: FieldKindCheckbox, Default: "true"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
	}
}

func (s *ScratchUDPAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	udp, err := s.AssembleUDP(values)
	if err != nil {
		return nil, err
	}
	udp.Data = payload

	// 自動計算のオン/オフ（オフにすれば「わざと不正な値」も送れる）
	if calc, err := boolFromValue(values["calc_length"]); err != nil {
		return nil, fmt.Errorf("calc_length: %w", err)
	} else if calc {
		udp.Len()
	}

	return udp.Bytes(), nil
}

// AssembleUDP は values から UDP 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、自動計算やL3連結はそちらの責務）へ
// 構造体を渡すために使う。
func (s *ScratchUDPAssembler) AssembleUDP(values map[string]any) (*UDP, error) {
	udp := &UDP{}
	var err error
	if udp.SrcPort, err = uint16FromValue(values["src_port"]); err != nil {
		return nil, fmt.Errorf("src_port: %w", err)
	}
	if udp.DstPort, err = uint16FromValue(values["dst_port"]); err != nil {
		return nil, fmt.Errorf("dst_port: %w", err)
	}
	if udp.Length, err = uint16FromValue(values["length"]); err != nil {
		return nil, fmt.Errorf("length: %w", err)
	}
	if udp.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	return udp, nil
}
