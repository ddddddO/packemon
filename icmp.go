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

	icmp.data = timestamp

	icmp.checksum = func() uint16 {
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, icmp.calculateChecksum())
		return binary.BigEndian.Uint16(b)
	}()

	return icmp
}

// copy from https://cs.opensource.google/go/x/net/+/master:icmp/message.go
func (i *icmp) calculateChecksum() uint16 {
	b := i.toBytes()
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
