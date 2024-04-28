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
	data     [4]uint8
}

const (
	ICMP_TYPE_REQUEST = 0x08
)

// TODO: データ部が仮でもできてない
func newICMP() *icmp {
	return &icmp{
		typ:      ICMP_TYPE_REQUEST,
		code:     0,
		checksum: 0xa7c0,
	}
}

func (i *icmp) toBytes() []byte {
	var buf bytes.Buffer
	buf.WriteByte(i.typ)
	buf.WriteByte(i.code)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.checksum)
	buf.Write(b)

	return buf.Bytes()
}
