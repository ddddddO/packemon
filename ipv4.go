package main

import (
	"bytes"
	"encoding/binary"
)

// https://www.infraexpert.com/study/tcpip1.html
type ipv4 struct {
	version        uint8  // 4bit
	ihl            uint8  // 4bit. hearder length
	tos            uint8  // 8bit. type of service
	totalLength    uint16 // 16bit. total length
	identification uint16 // 16bit
	flags          uint8  // 3bit
	fragmentOffset uint16 // 13bit
	ttl            uint8  // 8bit
	protocol       uint8  // 8bit
	headerChecksum uint16 // 16bit
	srcAddr        uint32 // 32bit
	dstAddr        uint32 // 32bit

	options []uint8
	padding []uint8

	data []byte
}

const (
	IPv4_PROTO_ICMP uint8 = 0x01
	IPv4_PROTO_UDP  uint8 = 0x11
)

// 一旦固定
func newIPv4(protocol uint8) *ipv4 {
	return &ipv4{
		version:        0x04,
		ihl:            0x05,
		tos:            0x00,
		totalLength:    0x54,
		identification: 0x0d94,
		flags:          0x40,
		fragmentOffset: 0x0,
		ttl:            0x40,
		protocol:       protocol,
		headerChecksum: 0,
		srcAddr:        0xac17f24e, // 172.23.242.78
		// dstAddr:        0x141bb171, // 20.27.177.113 = github.com
		dstAddr: 0x08080808, // 8.8.8.8 = DNSクエリ用
	}
}

func (i *ipv4) calculateTotalLength() {
	headerLength := 20 + len(i.options) + len(i.padding)
	i.totalLength = uint16(headerLength) + uint16(len(i.data))
}

// TODO: ここだけではないけど要refactor
func (i *ipv4) calculateChecksum() {
	header := make([]byte, 20)
	header = append(header, i.version<<4|i.ihl)
	header = append(header, i.tos)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.totalLength)
	header = append(header, b...)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.identification)
	header = append(header, b...)
	header = append(header, i.flags)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.fragmentOffset|uint16(i.ttl))
	header = append(header, b...)

	header = append(header, i.protocol)
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.headerChecksum)
	header = append(header, b...)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.srcAddr)
	header = append(header, b...)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.dstAddr)
	header = append(header, b...)

	i.headerChecksum = binary.BigEndian.Uint16(i.checksum(header))
}

// copy of https://github.com/sat0ken/go-curo/blob/main/utils.go#L18
func (i *ipv4) checksum(packet []byte) []byte {
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
		if i%2 == 0 {
			sum += uint(binary.BigEndian.Uint16(packet[i:]))
		}
	}
	return sum
}

func (i *ipv4) toBytes() []byte {
	var buf bytes.Buffer

	// Wireshark で他の正常なパケット見ると、versionとヘッダー長(ihl)が「45」
	// 以下コメントアウト部だと、「40 50」となりダメ
	// buf.WriteByte(i.version<<4)
	// buf.WriteByte(i.ihl<<4)
	buf.WriteByte(i.version<<4 | i.ihl)

	buf.WriteByte(i.tos)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.totalLength)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.identification)
	buf.Write(b)

	buf.WriteByte(i.flags)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.fragmentOffset|uint16(i.ttl))
	buf.Write(b)

	buf.WriteByte(i.protocol)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.headerChecksum)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.srcAddr)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.dstAddr)
	buf.Write(b)

	buf.Write(i.data)

	return buf.Bytes()
}
