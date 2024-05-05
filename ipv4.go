package packemon

import (
	"bytes"
	"encoding/binary"
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

const (
	IPv4_PROTO_ICMP uint8 = 0x01
	IPv4_PROTO_TCP  uint8 = 0x06
	IPv4_PROTO_UDP  uint8 = 0x11
)

// 一旦固定
func NewIPv4(protocol uint8, dstAddr uint32) *IPv4 {
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
		SrcAddr:        0xac17f24e, // 172.23.242.78
		DstAddr:        dstAddr,
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

	i.HeaderChecksum = binary.BigEndian.Uint16(i.Checksum(header))
}

// copy of https://github.com/sat0ken/go-curo/blob/main/utils.go#L18
func (*IPv4) Checksum(packet []byte) []byte {
	// まず16ビット毎に足す
	sum := sumByteArr(packet)
	// あふれた桁を足す
	sum = (sum & 0xffff) + sum>>16
	// 論理否定を取った値をbyteにして返す
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(sum^0xffff))
	return b
}

func sumByteArr(packet []byte) (sum uint) {
	for i := range packet {

		// ここ足した. icmpのreply返ってきてるし大丈夫そう
		if (i == len(packet)-2) && (len(packet)%2 != 0) {
			sum += uint(packet[i])
			break
		}

		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(packet[i:]))
		}
	}
	return sum
}

func (i *IPv4) Bytes() []byte {
	var buf bytes.Buffer

	// Wireshark で他の正常なパケット見ると、versionとヘッダー長(ihl)が「45」
	// 以下コメントアウト部だと、「40 50」となりダメ
	// buf.WriteByte(i.version<<4)
	// buf.WriteByte(i.ihl<<4)
	buf.WriteByte(i.Version<<4 | i.Ihl)

	buf.WriteByte(i.Tos)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.TotalLength)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.Identification)
	buf.Write(b)

	buf.WriteByte(i.Flags)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.FragmentOffset|uint16(i.Ttl))
	buf.Write(b)

	buf.WriteByte(i.Protocol)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.HeaderChecksum)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.SrcAddr)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.DstAddr)
	buf.Write(b)

	buf.Write(i.Data)

	return buf.Bytes()
}
