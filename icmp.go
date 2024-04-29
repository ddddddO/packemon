package main

import (
	"bytes"
	"encoding/binary"
)

// https://www.infraexpert.com/study/tcpip4.html
type icmp struct {
	typ      uint8
	code     uint8
	checksum uint16
	data     []byte
}

const (
	ICMP_TYPE_REQUEST = 0x08
)

// https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
func newICMP() *icmp {
	var (
	// identifier1 uint16 = 0x1234
	// identifier2 uint16 = 0x9876
	// sequence1 uint16 = 0x0001
	// sequence2 uint16 = 0x0100
	// data = make([]byte, 4)
	)

	return &icmp{
		typ:      ICMP_TYPE_REQUEST,
		code:     0,
		checksum: 0xe5ca,
		data:     []byte{0x12, 0x34, 0x98, 0x76, 0x00, 0x01, 0x01, 0x00},
	}
}

func (i *icmp) toBytes() []byte {
	var buf bytes.Buffer
	buf.WriteByte(i.typ)
	buf.WriteByte(i.code)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.checksum)
	buf.Write(b)

	buf.Write(i.data)

	return buf.Bytes()
}
