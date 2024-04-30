package main

import (
	"bytes"
	"encoding/binary"
)

// https://www.infraexpert.com/study/tcpip4.html
// https://inc0x0.com/icmp-ip-packets-ping-manually-create-and-send-icmp-ip-packets/
type icmp struct {
	typ        uint8
	code       uint8
	checksum   uint16
	identifier uint16
	sequence   uint16
	data       []byte
}

const (
	ICMP_TYPE_REQUEST = 0x08
)

// icmp request
func newICMP() *icmp {
	icmp := &icmp{
		typ:        ICMP_TYPE_REQUEST,
		code:       0,
		identifier: 0x1234,
		sequence:   0x0001,
	}

	checksum :=
		0xffff - (binary.BigEndian.Uint16([]byte{icmp.typ, icmp.code}) +
			icmp.identifier +
			icmp.sequence)

	icmp.checksum = checksum

	return icmp
}

func (i *icmp) toBytes() []byte {
	var buf bytes.Buffer
	buf.WriteByte(i.typ)
	buf.WriteByte(i.code)

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.checksum)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.identifier)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, i.sequence)
	buf.Write(b)

	buf.Write(i.data)

	return buf.Bytes()
}
