package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const ARP_HARDWARE_TYPE_THERNET = 0x0001

const ARP_PROTO_TYPE_IPv4 = 0x0800

const (
	ARP_OPERATION_CODE_REQUEST = 0x0001
	ARP_OPERATION_CODE_REPLY   = 0x0002
)

// https://ja.wikipedia.org/wiki/Address_Resolution_Protocol#%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E6%A7%8B%E9%80%A0
// https://beginners-network.com/supplement/arp_packet_format.html
type ARP struct {
	HardwareType       uint16
	ProtocolType       uint16
	HardwareAddrLength uint8
	ProtocolLength     uint8
	Operation          uint16

	SenderHardwareAddr HardwareAddr
	SenderIPAddr       uint32

	TargetHardwareAddr HardwareAddr
	TargetIPAddr       uint32
}

func (a *ARP) Bytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, a.HardwareType)
	WriteUint16(buf, a.ProtocolType)
	buf.WriteByte(a.HardwareAddrLength)
	buf.WriteByte(a.ProtocolLength)
	WriteUint16(buf, a.Operation)
	buf.Write(a.SenderHardwareAddr[:])
	WriteUint32(buf, a.SenderIPAddr)
	buf.Write(a.TargetHardwareAddr[:])
	WriteUint32(buf, a.TargetIPAddr)
	return buf.Bytes()
}

func ParsedARP(payload []byte) *ARP {
	return &ARP{
		HardwareType:       binary.BigEndian.Uint16(payload[0:2]),
		ProtocolType:       binary.BigEndian.Uint16(payload[2:4]),
		HardwareAddrLength: payload[4],
		ProtocolLength:     payload[5],
		Operation:          binary.BigEndian.Uint16(payload[6:8]),

		SenderHardwareAddr: HardwareAddr(payload[8:14]),
		SenderIPAddr:       binary.BigEndian.Uint32(payload[14:18]),

		TargetHardwareAddr: HardwareAddr(payload[18:24]),
		TargetIPAddr:       binary.BigEndian.Uint32(payload[24:28]),
	}
}

func NewARPRequest(sMACAdder HardwareAddr, sIPAddr uint32, tMACAddr HardwareAddr, tIPAddr uint32) *ARP {
	return &ARP{
		HardwareType:       ARP_HARDWARE_TYPE_THERNET,
		ProtocolType:       ARP_PROTO_TYPE_IPv4,
		HardwareAddrLength: 0x06, // イーサネットは6固定
		ProtocolLength:     0x04, // IPv4は4固定
		Operation:          ARP_OPERATION_CODE_REQUEST,

		SenderHardwareAddr: sMACAdder,
		SenderIPAddr:       sIPAddr,
		TargetHardwareAddr: tMACAddr,
		TargetIPAddr:       tIPAddr,
	}
}

func NewARPReply(sMACAdder HardwareAddr, sIPAddr uint32, tMACAddr HardwareAddr, tIPAddr uint32) *ARP {
	return &ARP{
		HardwareType:       ARP_HARDWARE_TYPE_THERNET,
		ProtocolType:       ARP_PROTO_TYPE_IPv4,
		HardwareAddrLength: 0x06,
		ProtocolLength:     0x04,
		Operation:          ARP_OPERATION_CODE_REPLY,

		SenderHardwareAddr: sMACAdder,
		SenderIPAddr:       sIPAddr,
		TargetHardwareAddr: tMACAddr,
		TargetIPAddr:       tIPAddr,
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (a *ARP) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "ARP",
		Children: []*FieldNode{
			{Name: "Hardware Type", Value: fmt.Sprintf("0x%04x", a.HardwareType)},
			{Name: "Protocol Type", Value: fmt.Sprintf("0x%04x", a.ProtocolType)},
			{Name: "Hardware Size", Value: fmt.Sprintf("0x%02x", a.HardwareAddrLength)},
			{Name: "Protocol Size", Value: fmt.Sprintf("0x%02x", a.ProtocolLength)},
			{Name: "Operation Code", Value: fmt.Sprintf("0x%04x", a.Operation)},
			{Name: "Sender Mac Addr", Value: a.SenderHardwareAddr.String()},
			{Name: "Sender IP Addr", Value: uint32ToIPv4Str(a.SenderIPAddr)},
			{Name: "Target Mac Addr", Value: a.TargetHardwareAddr.String()},
			{Name: "Target IP Addr", Value: uint32ToIPv4Str(a.TargetIPAddr)},
		},
	}
}

// ScratchARPAssembler は、スクラッチ実装（ARP.Bytes）による Assembler。
type ScratchARPAssembler struct{}

var _ Assembler = (*ScratchARPAssembler)(nil)

func (s *ScratchARPAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "hardware_type", Label: "Hardware Type", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "protocol_type", Label: "Protocol Type", Kind: FieldKindHex, Default: "0x0800"},
		{Key: "hardware_size", Label: "Hardware Size", Kind: FieldKindHex, Default: "0x06"},
		{Key: "protocol_size", Label: "Protocol Size", Kind: FieldKindHex, Default: "0x04"},
		{Key: "operation", Label: "Operation Code", Kind: FieldKindHex, Default: "0x0001"},
		{Key: "sender_mac", Label: "Sender Mac Addr", Kind: FieldKindText, Default: "00:00:00:00:00:00"},
		{Key: "sender_ip", Label: "Sender IP Addr", Kind: FieldKindText, Default: "0.0.0.0"},
		{Key: "target_mac", Label: "Target Mac Addr", Kind: FieldKindText, Default: "00:00:00:00:00:00"},
		{Key: "target_ip", Label: "Target IP Addr", Kind: FieldKindText, Default: "0.0.0.0"},
	}
}

func (s *ScratchARPAssembler) Assemble(values map[string]any, _ []byte) ([]byte, error) {
	// ARP は上位レイヤを持たないため payload は使わない
	arp, err := s.AssembleARP(values)
	if err != nil {
		return nil, err
	}
	return arp.Bytes(), nil
}

// AssembleARP は values から ARP 構造体を組み立てる。
// TUI の動的フォームが、既存の送信経路（sender の packets）へ構造体を渡すために使う。
func (s *ScratchARPAssembler) AssembleARP(values map[string]any) (*ARP, error) {
	arp := &ARP{}
	var err error
	if arp.HardwareType, err = uint16FromValue(values["hardware_type"]); err != nil {
		return nil, fmt.Errorf("hardware_type: %w", err)
	}
	if arp.ProtocolType, err = uint16FromValue(values["protocol_type"]); err != nil {
		return nil, fmt.Errorf("protocol_type: %w", err)
	}
	if arp.HardwareAddrLength, err = uint8FromValue(values["hardware_size"]); err != nil {
		return nil, fmt.Errorf("hardware_size: %w", err)
	}
	if arp.ProtocolLength, err = uint8FromValue(values["protocol_size"]); err != nil {
		return nil, fmt.Errorf("protocol_size: %w", err)
	}
	if arp.Operation, err = uint16FromValue(values["operation"]); err != nil {
		return nil, fmt.Errorf("operation: %w", err)
	}
	if arp.SenderHardwareAddr, err = hardwareAddrFromValue(values["sender_mac"]); err != nil {
		return nil, fmt.Errorf("sender_mac: %w", err)
	}
	if arp.SenderIPAddr, err = ipv4AddrFromValue(values["sender_ip"]); err != nil {
		return nil, fmt.Errorf("sender_ip: %w", err)
	}
	if arp.TargetHardwareAddr, err = hardwareAddrFromValue(values["target_mac"]); err != nil {
		return nil, fmt.Errorf("target_mac: %w", err)
	}
	if arp.TargetIPAddr, err = ipv4AddrFromValue(values["target_ip"]); err != nil {
		return nil, fmt.Errorf("target_ip: %w", err)
	}
	return arp, nil
}
