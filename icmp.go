package main

import (
	"bytes"
	"encoding/binary"
	"time"
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
		identifier: 0x34a1,
		sequence:   0x0001,
	}

	// pingのecho requestのpacketを観察すると以下で良さそう
	timestamp := func() []byte {
		now := time.Now().Unix()
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(now))
		return binary.LittleEndian.AppendUint32(b, 0x00000000)
	}()

	// これはあてになるかわからない。いらないかも
	data := []byte{
		0x77, 0xd9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	}
	icmp.data = append(timestamp, data...)
	// icmp.data = timestamp

	// 以下の求め方間違ってるっぽい.
	// なので、x/netからchecksum関数持ってきた.checksumのエラーはなくなった
	// checksum :=
	// 	0xffff - (binary.BigEndian.Uint16([]byte{icmp.typ, icmp.code}) +
	// 		icmp.identifier +
	// 		icmp.sequence)

	icmp.checksum = func() uint16 {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, checksum(icmp.toBytes()))
		return binary.BigEndian.Uint16(b)
	}()

	return icmp
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func checksum(b []byte) uint16 {
	csumcv := len(b) - 1 // checksum coverage
	s := uint32(0)
	for i := 0; i < csumcv; i += 2 {
		s += uint32(b[i+1])<<8 | uint32(b[i])
	}
	if csumcv&1 == 0 {
		s += uint32(b[csumcv])
	}
	s = s>>16 + s&0xffff
	s = s + s>>16
	return ^uint16(s)
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
