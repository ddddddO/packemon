package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func NewEthernetFrame(dst HardwareAddr, src HardwareAddr, typ uint16, payload []byte) *EthernetFrame {
	return &EthernetFrame{
		Header: &EthernetHeader{
			Dst: dst,
			Src: src,
			Typ: typ,
		},
		Data: payload,
	}
}

func ParsedEthernetFrame(b []byte) *EthernetFrame {
	eth := &EthernetHeader{
		Dst: HardwareAddr(b[0:6]),
		Src: HardwareAddr(b[6:12]),
		Typ: binary.BigEndian.Uint16(b[12:14]),
	}

	if eth.Typ == ETHER_TYPE_DOT1Q && len(b) >= 18 {
		eth.Dot1QFiels = &EthernetDot1QFields{
			Dot1QFiels: binary.BigEndian.Uint16(b[14:16]),
			Type:       binary.BigEndian.Uint16(b[16:18]),
		}

		if len(b) >= 19 {
			return &EthernetFrame{
				Header: eth,
				Data:   b[18:],
			}
		}
		return &EthernetFrame{
			Header: eth,
		}
	}

	return &EthernetFrame{
		Header: eth,
		Data:   b[14:],
	}
}

func (ef *EthernetFrame) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(ef.Header.Dst[:])
	buf.Write(ef.Header.Src[:])
	WriteUint16(buf, ef.Header.Typ)

	// Generator で、EtherType=DOT1Qを指定したときだけそれ用のフィールドを送信する、仕様
	if ef.Header.Typ == ETHER_TYPE_DOT1Q {
		WriteUint16(buf, ef.Header.Dot1QFiels.Dot1QFiels)
		WriteUint16(buf, ef.Header.Dot1QFiels.Type)
	}

	buf.Write(ef.Data)
	return buf.Bytes()
}

type EthernetFrame struct {
	Header *EthernetHeader
	Data   []byte
}

type EthernetHeader struct {
	Dst HardwareAddr
	Src HardwareAddr
	Typ uint16

	Dot1QFiels *EthernetDot1QFields
}

type EthernetDot1QFields struct {
	Dot1QFiels uint16
	Type       uint16

	// TODO: Dot1QFiels をさらに細分化
	// PriorityCodePoint        uint8  // 3bit
	// CanonicalFormatIndicator uint8  // 1bit
	// VLANID                   uint16 // 12bit
}

type HardwareAddr [6]uint8

func (h *HardwareAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4], h[5])
}

const ETHER_TYPE_IPv4 uint16 = 0x0800
const ETHER_TYPE_IPv6 uint16 = 0x86dd
const ETHER_TYPE_ARP uint16 = 0x0806
const ETHER_TYPE_DOT1Q uint16 = 0x8100 // IEEE 802.1Q, VLAN-tag

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
// スクラッチ実装（ScratchDissector）が使用する。
func (ef *EthernetFrame) FieldNode() *FieldNode {
	node := &FieldNode{
		Name: "Ethernet",
		Children: []*FieldNode{
			{Name: "Destination", Value: ef.Header.Dst.String()},
			{Name: "Source", Value: ef.Header.Src.String()},
			{Name: "Type", Value: fmt.Sprintf("0x%04x", ef.Header.Typ)},
		},
	}
	if ef.Header.Typ == ETHER_TYPE_DOT1Q && ef.Header.Dot1QFiels != nil {
		node.Children = append(node.Children,
			&FieldNode{Name: "802.1Q Fields", Value: fmt.Sprintf("0x%04x", ef.Header.Dot1QFiels.Dot1QFiels)},
			&FieldNode{Name: "802.1Q Type", Value: fmt.Sprintf("0x%04x", ef.Header.Dot1QFiels.Type)},
		)
	}
	return node
}

// ScratchEthernetAssembler は、スクラッチ実装（EthernetFrame.Bytes）による Assembler。
type ScratchEthernetAssembler struct{}

var _ Assembler = (*ScratchEthernetAssembler)(nil)

func (a *ScratchEthernetAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "dst", Label: "Destination Mac Addr", Kind: FieldKindText, Default: "00:00:00:00:00:00"},
		{Key: "src", Label: "Source Mac Addr", Kind: FieldKindText, Default: "00:00:00:00:00:00"},
		{Key: "ether_type", Label: "Ether Type", Kind: FieldKindSelectOrHex, Default: "IPv4", Options: []string{"IPv4", "IPv6", "ARP", "Dot1Q"}},
		{Key: "dot1q_fields", Label: "PCP/CFI/VLANID(EtherType=Dot1Q is required)", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "dot1q_type", Label: "Type(EtherType=Dot1Q is required)", Kind: FieldKindHex, Default: "0x0800"},
	}
}

func (a *ScratchEthernetAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	header, err := a.AssembleEthernetHeader(values)
	if err != nil {
		return nil, err
	}

	frame := &EthernetFrame{Header: header, Data: payload}
	return frame.Bytes(), nil
}

// AssembleEthernetHeader は values から EthernetHeader 構造体を組み立てる。
// TUI の動的フォームが、既存の送信経路（sender の packets）へ構造体を渡すために使う。
// Dot1Q のフィールドは未指定ならゼロ値相当で設定する（Bytes は EtherType=Dot1Q のときだけ書き出す）。
func (a *ScratchEthernetAssembler) AssembleEthernetHeader(values map[string]any) (*EthernetHeader, error) {
	dst, err := hardwareAddrFromValue(values["dst"])
	if err != nil {
		return nil, fmt.Errorf("dst: %w", err)
	}
	src, err := hardwareAddrFromValue(values["src"])
	if err != nil {
		return nil, fmt.Errorf("src: %w", err)
	}
	typ, err := etherTypeFromValue(values["ether_type"])
	if err != nil {
		return nil, fmt.Errorf("ether_type: %w", err)
	}

	dot1q := &EthernetDot1QFields{Dot1QFiels: 0x0000, Type: 0x0800}
	if v, ok := values["dot1q_fields"]; ok && v != nil {
		if dot1q.Dot1QFiels, err = uint16FromValue(v); err != nil {
			return nil, fmt.Errorf("dot1q_fields: %w", err)
		}
	}
	if v, ok := values["dot1q_type"]; ok && v != nil {
		if dot1q.Type, err = uint16FromValue(v); err != nil {
			return nil, fmt.Errorf("dot1q_type: %w", err)
		}
	}

	return &EthernetHeader{Dst: dst, Src: src, Typ: typ, Dot1QFiels: dot1q}, nil
}

// etherTypeFromValue は、プロトコル名（"IPv4" 等。TUI の選択肢）、"0x0800" 等の文字列、
// または uint16 そのものを受け付ける。
func etherTypeFromValue(v any) (uint16, error) {
	if s, ok := v.(string); ok {
		switch s {
		case "IPv4":
			return ETHER_TYPE_IPv4, nil
		case "IPv6":
			return ETHER_TYPE_IPv6, nil
		case "ARP":
			return ETHER_TYPE_ARP, nil
		case "Dot1Q":
			return ETHER_TYPE_DOT1Q, nil
		}
	}
	return uint16FromValue(v)
}

// GopacketEthernetAssembler は、gopacket（SerializeLayers）による Ethernet の Assembler。
// フィールド定義（Fields）はスクラッチ版と共通で、TUI からはバックエンドとして差し替え可能。
type GopacketEthernetAssembler struct{}

var _ Assembler = (*GopacketEthernetAssembler)(nil)

func (a *GopacketEthernetAssembler) Fields() []FieldSpec {
	// values のキー・入力形式はスクラッチ版と互換（バックエンド差し替えのため）
	return (&ScratchEthernetAssembler{}).Fields()
}

func (a *GopacketEthernetAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	dst, err := hardwareAddrFromValue(values["dst"])
	if err != nil {
		return nil, fmt.Errorf("dst: %w", err)
	}
	src, err := hardwareAddrFromValue(values["src"])
	if err != nil {
		return nil, fmt.Errorf("src: %w", err)
	}
	typ, err := etherTypeFromValue(values["ether_type"])
	if err != nil {
		return nil, fmt.Errorf("ether_type: %w", err)
	}

	eth := &layers.Ethernet{
		DstMAC:       dst[:],
		SrcMAC:       src[:],
		EthernetType: layers.EthernetType(typ),
	}

	headerLen := 14
	serializeLayers := []gopacket.SerializableLayer{eth}
	if typ == ETHER_TYPE_DOT1Q {
		dot1qFields := uint16(0x0000)
		if v, ok := values["dot1q_fields"]; ok && v != nil {
			if dot1qFields, err = uint16FromValue(v); err != nil {
				return nil, fmt.Errorf("dot1q_fields: %w", err)
			}
		}
		dot1qType := uint16(0x0800)
		if v, ok := values["dot1q_type"]; ok && v != nil {
			if dot1qType, err = uint16FromValue(v); err != nil {
				return nil, fmt.Errorf("dot1q_type: %w", err)
			}
		}
		serializeLayers = append(serializeLayers, &layers.Dot1Q{
			Priority:       uint8(dot1qFields >> 13), // PCP: 上位3bit
			DropEligible:   dot1qFields&0x1000 != 0,  // CFI/DEI: 1bit
			VLANIdentifier: dot1qFields & 0x0fff,     // VLAN ID: 下位12bit
			Type:           layers.EthernetType(dot1qType),
		})
		headerLen += 4
	}
	serializeLayers = append(serializeLayers, gopacket.Payload(payload))

	buf := gopacket.NewSerializeBuffer()
	// 任意の値をそのまま送れるよう、長さ・チェックサムの自動補正はしない
	opts := gopacket.SerializeOptions{FixLengths: false, ComputeChecksums: false}
	if err := gopacket.SerializeLayers(buf, opts, serializeLayers...); err != nil {
		return nil, err
	}

	// gopacket の layers.Ethernet は最小フレーム長（60バイト、FCS除く）まで無条件で
	// ゼロパディングする。スクラッチ版はパディングせずカーネルに任せる方針のため、
	// バックエンド間で送信バイト列が変わらないようパディングを取り除く。
	assembled := buf.Bytes()
	if want := headerLen + len(payload); len(assembled) > want {
		assembled = assembled[:want]
	}
	return assembled, nil
}

// gopacketEthernetFieldNode は、gopacket でパースした Ethernet ヘッダの表示ツリー。
// 表示項目・フォーマットはスクラッチ版（EthernetHeader.FieldNode）と揃える。
func gopacketEthernetFieldNode(eth *layers.Ethernet) *FieldNode {
	return &FieldNode{
		Name: "Ethernet",
		Children: []*FieldNode{
			{Name: "Destination", Value: eth.DstMAC.String()},
			{Name: "Source", Value: eth.SrcMAC.String()},
			{Name: "Type", Value: fmt.Sprintf("0x%04x (%s)", uint16(eth.EthernetType), eth.EthernetType)},
		},
	}
}
