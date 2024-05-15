package packemon

import (
	"bytes"
)

const (
	// 最後0付けてるけど、Wireshark上だと不要。受信時、TCP.Flags を4bit左シフトしてるからここでも付けてる
	TCP_FLAGS_SYN     = 0x0020
	TCP_FLAGS_SYN_ACK = 0x0120
	TCP_FLAGS_ACK     = 0x0100
	TCP_FLAGS_PSH_ACK = 0x0180 // データを上位層へ渡してという信号
)

type TCP struct {
	SrcPort        uint16
	DstPort        uint16
	Sequence       uint32
	Acknowledgment uint32
	// HeaderLength uint8
	HeaderLength  uint16
	Flags         uint16 // flagsをセットする用の関数あったほうがいいかも？
	Window        uint16
	Checksum      uint16
	UrgentPointer uint16
	Options       []byte // optionsをセットする用の関数あった方がいいかも？

	Data []byte
}

// tcpパケット単発で連続で送るときは port/sequence 変えること
func NewTCPSyn() *TCP {
	return &TCP{
		SrcPort:        0x9e16, // 40470
		DstPort:        0x0050, // 80
		Sequence:       0x1f6e9499,
		Acknowledgment: 0x00000000,
		HeaderLength:   0x00a0,
		Flags:          0x002, // syn
		Window:         0xfaf0,
		Checksum:       0x0000,
		UrgentPointer:  0x0000,
		Options:        Options(),
	}
}

// tcpパケット単発で連続で送るときは port/sequence 変えること
func NewTCPAck(prevSequence uint32, prevAcknowledgment uint32) *TCP {
	return &TCP{
		SrcPort:        0x9e16, // 40470
		DstPort:        0x0050, // 80
		Sequence:       prevAcknowledgment,
		Acknowledgment: prevSequence + 0x00000001,
		HeaderLength:   0x00a0,
		Flags:          0x010, // ack
		Window:         0xfaf0,
		Checksum:       0x0000,
		UrgentPointer:  0x0000,
		Options:        OptionsOfAck(),
	}
}

// tcpパケット単発で連続で送るときは port/sequence 変えること
func NewTCPWithData(data []byte) *TCP {
	return &TCP{
		SrcPort:        0x9e12,
		DstPort:        0x0050, // 80
		Sequence:       0x1f6e9616,
		Acknowledgment: 0x00000000,
		HeaderLength:   0x0080,
		Flags:          0x0018, // psh,ack
		Window:         0xfaf0,
		Checksum:       0x0000,
		UrgentPointer:  0x0000,
		Options:        OptionsOfhttp(),
		Data:           data,
	}
}

func (*TCP) CheckSum(packet []byte) []byte {
	return (*IPv4)(nil).Checksum(packet)
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

	// t.headerLengthは、フォーマットでは「データオフセット」で4bit
	// t.flagsは、フォーマット的には、「予約」+「コントロールフラグ」
	WriteUint16(buf, t.HeaderLength<<8|t.Flags)
	WriteUint16(buf, t.Window)
	WriteUint16(buf, t.Checksum)
	WriteUint16(buf, t.UrgentPointer)
	buf.Write(t.Options)
	return buf.Bytes()
}

type Mss struct {
	Kind   uint8
	Length uint8
	Value  uint16
}

type SackPermitted struct {
	Kind   uint8
	Length uint8
}

type Timestamps struct {
	Kind      uint8
	Length    uint8
	Value     uint32
	EchoReply uint32
}

type NoOperation struct {
	Kind uint8
}

type WindowScale struct {
	Kind       uint8
	Length     uint8
	ShiftCount uint8
}

// synパケットの中を覗いて下
func Options() []byte {
	buf := &bytes.Buffer{}

	m := &Mss{
		Kind:   0x02,
		Length: 0x04,
		Value:  0x05b4, // 1460
	}
	buf.WriteByte(m.Kind)
	buf.WriteByte(m.Length)
	WriteUint16(buf, m.Value)

	s := &SackPermitted{
		Kind:   0x04,
		Length: 0x02,
	}
	buf.WriteByte(s.Kind)
	buf.WriteByte(s.Length)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0x73297ad7,
		EchoReply: 0x00000000,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)

	w := &WindowScale{
		Kind:       0x03,
		Length:     0x03,
		ShiftCount: 0x07,
	}
	buf.WriteByte(w.Kind)
	buf.WriteByte(w.Length)
	buf.WriteByte(w.ShiftCount)

	return buf.Bytes()
}

// synパケットの中を覗いて下
func OptionsOfAck() []byte {
	buf := &bytes.Buffer{}

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)
	buf.WriteByte(n.Kind)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0x73297ad7,
		EchoReply: 0x00000000,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)

	return buf.Bytes()
}

// http getリクエスト時のtcp optionを覗いて
// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
// 「オプション」フィールド：32bit単位で可変長
func OptionsOfhttp() []byte {
	buf := &bytes.Buffer{}

	n := &NoOperation{
		Kind: 0x01,
	}
	buf.WriteByte(n.Kind)
	buf.WriteByte(n.Kind)

	t := &Timestamps{
		Kind:      0x08,
		Length:    0x0a,
		Value:     0x817338b5,
		EchoReply: 0x409e9657,
	}
	buf.WriteByte(t.Kind)
	buf.WriteByte(t.Length)
	WriteUint32(buf, t.Value)
	WriteUint32(buf, t.EchoReply)
	// padding := []byte{0x00, 0x00, 0x00}
	// buf.Write(padding)

	return buf.Bytes()
}
