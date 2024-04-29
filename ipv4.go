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
	IPv4_PROTO_ICMP = 0x01
	IPv4_PROTO_UDP  = 0x11
)

// 一旦固定
func newIPv4() *ipv4 {
	return &ipv4{
		version:        0x04,
		ihl:            0x05,
		tos:            0x00,
		totalLength:    0x14,
		identification: 0xe31f,
		flags:          0x0,
		fragmentOffset: 0x0,
		ttl:            0x80,
		protocol:       IPv4_PROTO_UDP,
		headerChecksum: 0x0f55,
		srcAddr:        0xc0a86358, // 192.168.99.88
		dstAddr:        0xc0a86301, // 192.168.99.1
	}
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