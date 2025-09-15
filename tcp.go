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
