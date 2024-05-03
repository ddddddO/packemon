package main

import (
	"bytes"
	"encoding/binary"
)

type udp struct {
	srcPort  uint16
	dstPort  uint16
	length   uint16
	checksum uint16 // TODO: 後で計算用メソッドを。そもそも他のヘッダのchecksumと同じ計算っぽいから、独立させるかも
	data     []byte
}

func (u *udp) len() {
	length := 0
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.srcPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.dstPort)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.length)
	length += len(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.checksum)
	length += len(b)

	length += len(u.data)
	u.length = uint16(length)
}

func (u *udp) toBytes() []byte {
	var buf bytes.Buffer
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.srcPort)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.dstPort)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.length)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, u.checksum)
	buf.Write(b)

	buf.Write(u.data)

	return buf.Bytes()
}
