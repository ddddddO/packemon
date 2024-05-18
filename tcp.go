package packemon

import (
	"bytes"
	"encoding/binary"
	"log"
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
		SrcPort:        0x9e20, // 40474
		DstPort:        0x0050, // 80
		Sequence:       0x1f6e9502,
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
		SrcPort:        0x9e20, // 40474
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
		Value:     0xdbe1c2c4,
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
		Value:     0xdbe1c2c4,
		EchoReply: 0x796a7651,
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

func Aaaa() error {
	log.Println("in Aaaaa")
	nwt, err := NewNetworkInterfaceForTCP()
	if err != nil {
		return err
	}

	dstIPAddr := make([]byte, 4)
	binary.BigEndian.PutUint32(dstIPAddr, 0xc0a80a6e) // 192.168.10.110
	var dstPort uint16 = 0x0050                       // 80
	if err := nwt.Connect(dstIPAddr, dstPort); err != nil {
		return err
	}
	defer nwt.Close()

	return nil
}

// 3Wayhandshake
// func EstablishConnection() error {
// 	log.Println("in EstablishConnection")

// 	// --- syn packet ---

// 	tcp := NewTCPSyn()
// 	ipv4 := NewIPv4(IPv4_PROTO_TCP, 0xc0a80a6e) // 192.168.10.110 = raspi
// 	tcp.Checksum = func() uint16 {
// 		pseudoTCPHeader := func() []byte {
// 			buf := &bytes.Buffer{}
// 			WriteUint32(buf, ipv4.SrcAddr)
// 			WriteUint32(buf, ipv4.DstAddr)
// 			padding := byte(0x00)
// 			buf.WriteByte(padding)
// 			buf.WriteByte(ipv4.Protocol)
// 			WriteUint16(buf, uint16(len(tcp.Bytes())))
// 			return buf.Bytes()
// 		}()

// 		forTCPChecksum := &bytes.Buffer{}
// 		forTCPChecksum.Write(pseudoTCPHeader)
// 		forTCPChecksum.Write(tcp.Bytes())
// 		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
// 	}()
// 	ipv4.Data = tcp.Bytes()
// 	ipv4.CalculateTotalLength()
// 	ipv4.CalculateChecksum()

// 	nwt, err := NewNetworkInterfaceForTCP()
// 	if err != nil {
// 		return err
// 	}
// 	defer unix.Close(nwt.Socket)

// 	// --- send syn packet ---
// 	log.Println("send syn packet")

// 	dstIPAddr := make([]byte, 4)
// 	binary.BigEndian.PutUint32(dstIPAddr, ipv4.DstAddr)
// 	if err := nwt.SendIPv4Packet(dstIPAddr, tcp.DstPort, ipv4.Bytes()); err != nil {
// 		return err
// 	}

// 	// --- recieve syn/ack packet ---
// 	log.Println("recieve syn/ack packet")
// 	synack, err := nwt.RecieveTCPSynAck(dstIPAddr)
// 	if err != nil {
// 		return err
// 	}

// 	// --- send ack packet ---
// 	log.Println("send ack packet")

// 	// syn/ackを受け取ったのでack送信
// 	tcp = NewTCPAck(synack.Sequence, synack.Acknowledgment)
// 	ipv4 = NewIPv4(IPv4_PROTO_TCP, 0xc0a80a6e) // 192.168.10.110 = raspi
// 	tcp.Checksum = func() uint16 {
// 		pseudoTCPHeader := func() []byte {
// 			buf := &bytes.Buffer{}
// 			WriteUint32(buf, ipv4.SrcAddr)
// 			WriteUint32(buf, ipv4.DstAddr)
// 			padding := byte(0x00)
// 			buf.WriteByte(padding)
// 			buf.WriteByte(ipv4.Protocol)
// 			WriteUint16(buf, uint16(len(tcp.Bytes())))
// 			return buf.Bytes()
// 		}()

// 		forTCPChecksum := &bytes.Buffer{}
// 		forTCPChecksum.Write(pseudoTCPHeader)
// 		forTCPChecksum.Write(tcp.Bytes())
// 		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
// 	}()
// 	ipv4.Data = tcp.Bytes()
// 	ipv4.CalculateTotalLength()
// 	ipv4.CalculateChecksum()

// 	binary.BigEndian.PutUint32(dstIPAddr, ipv4.DstAddr)
// 	if err := nwt.SendIPv4Packet(dstIPAddr, tcp.DstPort, ipv4.Bytes()); err != nil {
// 		return err
// 	}

// 	log.Println("Established?")

// 	return nil
// }
