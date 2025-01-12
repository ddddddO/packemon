package packemon

import (
	"bytes"
	"encoding/binary"
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
