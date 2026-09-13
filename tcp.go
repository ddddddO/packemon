package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

type TCPFlags uint8

const (
	TCP_FLAGS_SYN         TCPFlags = 0x02
	TCP_FLAGS_SYN_ACK     TCPFlags = 0x12
	TCP_FLAGS_ACK         TCPFlags = 0x10
	TCP_FLAGS_FIN_ACK     TCPFlags = 0x11
	TCP_FLAGS_PSH_ACK     TCPFlags = 0x18 // データを上位層へ渡してという信号
	TCP_FLAGS_FIN_PSH_ACK TCPFlags = 0x19
	TCP_FLAGS_RST_ACK     TCPFlags = 0x14
)

func (tf TCPFlags) String() string {
	switch tf {
	case TCP_FLAGS_SYN:
		return "Syn"
	case TCP_FLAGS_SYN_ACK:
		return "Syn/Ack"
	case TCP_FLAGS_ACK:
		return "Ack"
	case TCP_FLAGS_FIN_ACK:
		return "Fin/Ack"
	case TCP_FLAGS_PSH_ACK:
		return "Psh/Ack"
	case TCP_FLAGS_FIN_PSH_ACK:
		return "Fin/Psh/Ack"
	case TCP_FLAGS_RST_ACK:
		return "Rst/Ack"
	default:
		return fmt.Sprintf("raw: %x", uint8(tf))
	}
}

type TCP struct {
	SrcPort        uint16
	DstPort        uint16
	Sequence       uint32
	Acknowledgment uint32

	// Data Offset (DOffset)(4bit. TCPヘッダ長. 32bit整数倍) と Reserved (Rsrvd)(4bit. すべて0)
	// ref: https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1
	HeaderLength uint8

	// Control bits(8bit)
	// ref: https://www.rfc-editor.org/rfc/rfc9293.html#section-3.1-6.14.1
	Flags TCPFlags

	Window        uint16
	Checksum      uint16
	UrgentPointer uint16
	Options       []byte // optionsをセットする用の関数あった方がいいかも？

	Data []byte
}

func ParsedTCP(payload []byte) *TCP {
	tcp := &TCP{
		SrcPort:        binary.BigEndian.Uint16(payload[0:2]),
		DstPort:        binary.BigEndian.Uint16(payload[2:4]),
		Sequence:       binary.BigEndian.Uint32(payload[4:8]),
		Acknowledgment: binary.BigEndian.Uint32(payload[8:12]),
		HeaderLength:   payload[12] & 0b11110000,
		Flags:          TCPFlags(payload[13]),
		Window:         binary.BigEndian.Uint16(payload[14:16]),
		Checksum:       binary.BigEndian.Uint16(payload[16:18]),
		UrgentPointer:  binary.BigEndian.Uint16(payload[18:20]),
	}

	// Wiresharkとpackemonのパケット詳細見比べるに、
	// ( tcpヘッダーのheader lengthを10進数に変換した値 / 4 ) - 20 = options のbyte数 になるよう
	optionLength := tcp.HeaderLength>>2 - 20
	if optionLength > 0 {
		tcp.Options = payload[20 : optionLength+20]
	}
	tcp.Data = payload[optionLength+20:]

	// tcp.Data = payload[20:]
	return tcp
}

func newTCP(flags uint8, srcPort, dstPort uint16, sequence, acknowledgment uint32, data []byte) *TCP {
	return &TCP{
		SrcPort:        srcPort,
		DstPort:        dstPort,
		Sequence:       sequence,
		Acknowledgment: acknowledgment,
		HeaderLength:   0x0050,
		Flags:          TCPFlags(flags),
		Window:         0xfaf0,
		Checksum:       0x0000,
		UrgentPointer:  0x0000,
		// Options:        Options(),

		Data: data,
	}
}

// tcpパケット単発で連続で送るときは port/sequence 変えること
func NewTCPSyn(srcPort, dstPort uint16) *TCP {
	return newTCP(0x02 /** syn **/, srcPort, dstPort, 0x091f58f9, 0x00000000, nil)
}

// tcpパケット連続で送るときは port 変えること
func NewTCPAck(srcPort, dstPort uint16, prevSequence uint32, prevAcknowledgment uint32) *TCP {
	return newTCP(0x10 /** ack **/, srcPort, dstPort, prevAcknowledgment, prevSequence+0x00000001, nil)
}

// tcpパケット連続で送るときは port 変えること
func NewTCPAckForPassiveData(srcPort, dstPort uint16, prevSequence uint32, prevAcknowledgment uint32, tcpPayloadLength int) *TCP {
	return newTCP(0x10 /** ack **/, srcPort, dstPort, prevAcknowledgment, prevSequence+uint32(tcpPayloadLength), nil)
}

// tcpパケット連続で送るときは port 変えること
func NewTCPWithData(srcPort, dstPort uint16, data []byte, prevSequence uint32, prevAcknowledgment uint32) *TCP {
	return newTCP(0x18 /** push/ack **/, srcPort, dstPort, prevSequence, prevAcknowledgment, data)
}

// tcpパケット連続で送るときは port 変えること
func NewTCPFinAck(srcPort, dstPort uint16, prevSequence uint32, prevAcknowledgment uint32) *TCP {
	return newTCP(0x11 /** fin/ack **/, srcPort, dstPort, prevSequence, prevAcknowledgment, nil)
}

// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
// 「「チェックサム」フィールド：16bit幅」
func (t *TCP) CalculateChecksum(ipv4 *IPv4) {
	t.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			buf := &bytes.Buffer{}
			WriteUint32(buf, ipv4.SrcAddr)
			WriteUint32(buf, ipv4.DstAddr)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			WriteUint16(buf, uint16(len(t.Bytes())))
			return buf.Bytes()
		}()

		forTCPChecksum := &bytes.Buffer{}
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(t.Bytes())
		if len(t.Data)%2 != 0 {
			forTCPChecksum.WriteByte(0x00)
		}
		return binary.BigEndian.Uint16(t.checksum(forTCPChecksum.Bytes()))
	}()
}

func (t *TCP) CalculateChecksumForIPv6(ipv6 *IPv6) {
	pseudoHeader := ipv6.PseudoHeader(uint32(len(t.Bytes())))
	forTCPChecksum := &bytes.Buffer{}
	forTCPChecksum.Write(pseudoHeader)
	forTCPChecksum.Write(t.Bytes())
	if len(t.Data)%2 != 0 {
		forTCPChecksum.WriteByte(0x00)
	}

	data := forTCPChecksum.Bytes()
	t.Checksum = binary.BigEndian.Uint16(calculateChecksum(data))
}

func (*TCP) checksum(packet []byte) []byte {
	return calculateChecksum(packet)
}

// https://www.infraexpert.com/study/tcpip8.html
func (t *TCP) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(t.headerToBytes())
	buf.Write(t.Data)
	return buf.Bytes()
}

func (t *TCP) headerToBytes() []byte {
	buf := &bytes.Buffer{}
	WriteUint16(buf, t.SrcPort)
	WriteUint16(buf, t.DstPort)
	WriteUint32(buf, t.Sequence)
	WriteUint32(buf, t.Acknowledgment)
	buf.WriteByte(t.HeaderLength)
	buf.WriteByte(uint8(t.Flags))
	WriteUint16(buf, t.Window)
	WriteUint16(buf, t.Checksum)
	WriteUint16(buf, t.UrgentPointer)
	buf.Write(t.Options)
	return buf.Bytes()
}

// with tcp 3 way handshake
func EstablishConnectionAndSendPayload(nwInterface string, dstIPAddr []byte, dstPort uint16, payload []byte) error {
	nwt, err := NewNetworkInterfaceForTCP(nwInterface)
	if err != nil {
		return err
	}

	if err := nwt.Connect(dstIPAddr, dstPort); err != nil {
		return err
	}
	defer nwt.Close()

	if _, err := nwt.Write(payload); err != nil {
		return err
	}

	return nil
}

func createTCPAddr(ipBytes []byte, port uint16) (*net.TCPAddr, error) {
	if len(ipBytes) != net.IPv4len && len(ipBytes) != net.IPv6len {
		return nil, fmt.Errorf("invalid IP addr length: %d bytes", len(ipBytes))
	}

	return &net.TCPAddr{
		IP:   net.IP(ipBytes),
		Port: int(port),
	}, nil
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TCP) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TCP",
		Children: []*FieldNode{
			{Name: "Source Port", Value: fmt.Sprintf("%#x (%d)", t.SrcPort, t.SrcPort)},
			{Name: "Destination Port", Value: fmt.Sprintf("%#x (%d)", t.DstPort, t.DstPort)},
			{Name: "Sequence", Value: fmt.Sprintf("0x%08x", t.Sequence)},
			{Name: "Acknowledgment", Value: fmt.Sprintf("0x%08x", t.Acknowledgment)},
			{Name: "Header Length", Value: fmt.Sprintf("0x%02x", t.HeaderLength)},
			{Name: "Flags", Value: fmt.Sprintf("0x%02x (%s)", uint8(t.Flags), t.Flags.String())},
			{Name: "Window", Value: fmt.Sprintf("0x%04x", t.Window)},
			{Name: "Checksum", Value: fmt.Sprintf("0x%04x", t.Checksum)},
			{Name: "Urgent Pointer", Value: fmt.Sprintf("0x%04x", t.UrgentPointer)},
		},
	}
}

// ScratchTCPAssembler は、スクラッチ実装（TCP.Bytes）による Assembler。
// ※ Checksum の自動計算は擬似ヘッダ（IPv4/IPv6 の情報）が必要なためこの層では行わない。
//
//	スタック連結時の再計算は上位（sender 側）の責務とする。 TODO: スタック連結の仕組みで扱う
type ScratchTCPAssembler struct{}

var _ Assembler = (*ScratchTCPAssembler)(nil)

func (s *ScratchTCPAssembler) Fields() []FieldSpec {
	return []FieldSpec{
		{Key: "src_port", Label: "Source Port", Kind: FieldKindText, Default: "47000"},
		{Key: "dst_port", Label: "Destination Port", Kind: FieldKindText, Default: "80"},
		{Key: "sequence", Label: "Sequence", Kind: FieldKindHex, Default: "0x1f6e9499"},
		{Key: "acknowledgment", Label: "Acknowledgment", Kind: FieldKindHex, Default: "0x00000000"},
		{Key: "header_length", Label: "Header Length", Kind: FieldKindHex, Default: "0x50"},
		{Key: "flags", Label: "Flags", Kind: FieldKindHex, Default: "0x02"},
		{Key: "window", Label: "Window", Kind: FieldKindHex, Default: "0xfaf0"},
		{Key: "checksum", Label: "Checksum", Kind: FieldKindHex, Default: "0x0000"},
		{Key: "urgent_pointer", Label: "Urgent Pointer", Kind: FieldKindHex, Default: "0x0000"},
	}
}

func (s *ScratchTCPAssembler) Assemble(values map[string]any, payload []byte) ([]byte, error) {
	tcp, err := s.AssembleTCP(values)
	if err != nil {
		return nil, err
	}
	tcp.Data = payload
	return tcp.Bytes(), nil
}

// AssembleTCP は values から TCP 構造体を組み立てる（自動計算は行わず生値のまま）。
// TUI の動的フォームが、既存の送信経路（sender の packets、checksum計算・L3連結・3way handshake は
// そちらの責務）へ構造体を渡すために使う。
func (s *ScratchTCPAssembler) AssembleTCP(values map[string]any) (*TCP, error) {
	tcp := &TCP{}
	var err error
	if tcp.SrcPort, err = uint16FromValue(values["src_port"]); err != nil {
		return nil, fmt.Errorf("src_port: %w", err)
	}
	if tcp.DstPort, err = uint16FromValue(values["dst_port"]); err != nil {
		return nil, fmt.Errorf("dst_port: %w", err)
	}
	if tcp.Sequence, err = uint32FromValue(values["sequence"]); err != nil {
		return nil, fmt.Errorf("sequence: %w", err)
	}
	if tcp.Acknowledgment, err = uint32FromValue(values["acknowledgment"]); err != nil {
		return nil, fmt.Errorf("acknowledgment: %w", err)
	}
	if tcp.HeaderLength, err = uint8FromValue(values["header_length"]); err != nil {
		return nil, fmt.Errorf("header_length: %w", err)
	}
	flags, err := uint8FromValue(values["flags"])
	if err != nil {
		return nil, fmt.Errorf("flags: %w", err)
	}
	tcp.Flags = TCPFlags(flags)
	if tcp.Window, err = uint16FromValue(values["window"]); err != nil {
		return nil, fmt.Errorf("window: %w", err)
	}
	if tcp.Checksum, err = uint16FromValue(values["checksum"]); err != nil {
		return nil, fmt.Errorf("checksum: %w", err)
	}
	if tcp.UrgentPointer, err = uint16FromValue(values["urgent_pointer"]); err != nil {
		return nil, fmt.Errorf("urgent_pointer: %w", err)
	}
	return tcp, nil
}
