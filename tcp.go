package main

import (
	"bytes"
	"encoding/binary"
)

type tcp struct {
	srcPort        uint16
	dstPort        uint16
	sequence       uint32
	acknowledgment uint32
	// headerLength uint8
	headerLength  uint16
	flags         uint16 // flagsをセットする用の関数あったほうがいいかも？
	window        uint16
	checksum      uint16
	urgentPointer uint16
	options       []byte // optionsをセットする用の関数あった方がいいかも？

	data []byte
}

// tcpパケット単発で連続で送るときは port/sequence 変えること
func newTCPSyn() *tcp {
	return &tcp{
		srcPort:        0x9e03,
		dstPort:        0x0050, // 80
		sequence:       0x1f6e9497,
		acknowledgment: 0x00000000,
		headerLength:   0x00a0,
		flags:          0x002, // syn
		window:         0xfaf0,
		checksum:       0x0000,
		urgentPointer:  0x0000,
		options:        options(),
	}
}

func (*tcp) checkSum(packet []byte) []byte {
	return (*ipv4)(nil).checksum(packet)
}

// https://www.infraexpert.com/study/tcpip8.html
func (t *tcp) toBytes() []byte {
	var buf bytes.Buffer
	buf.Write(t.headerToBytes())
	buf.Write(t.data)

	return buf.Bytes()
}

func (t *tcp) headerToBytes() []byte {
	var buf bytes.Buffer
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.srcPort)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.dstPort)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, t.sequence)
	buf.Write(b)

	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, t.acknowledgment)
	buf.Write(b)

	// t.headerLengthは、フォーマットでは「データオフセット」で4bit
	// t.flagsは、フォーマット的には、「予約」+「コントロールフラグ」
	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.headerLength<<8|t.flags)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.window)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.checksum)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, t.urgentPointer)
	buf.Write(b)

	buf.Write(t.options)

	return buf.Bytes()
}

// synパケットの中を覗いて下
func options() []byte {
	var buf bytes.Buffer

	type mss struct {
		kind   uint8
		length uint8
		value  uint16
	}
	m := &mss{
		kind:   0x02,
		length: 0x04,
		value:  0x05b4, // 1460
	}
	buf.WriteByte(m.kind)
	buf.WriteByte(m.length)
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, m.value)
	buf.Write(b)

	type sackPermitted struct {
		kind   uint8
		length uint8
	}
	s := &sackPermitted{
		kind:   0x04,
		length: 0x02,
	}
	buf.WriteByte(s.kind)
	buf.WriteByte(s.length)

	type timestamps struct {
		kind      uint8
		length    uint8
		value     uint32
		echoReply uint32
	}
	t := &timestamps{
		kind:      0x08,
		length:    0x0a,
		value:     0x73297ad7,
		echoReply: 0x00000000,
	}
	buf.WriteByte(t.kind)
	buf.WriteByte(t.length)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, t.value)
	buf.Write(b)
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, t.echoReply)
	buf.Write(b)

	type noOperation struct {
		kind uint8
	}
	n := &noOperation{
		kind: 0x01,
	}
	buf.WriteByte(n.kind)

	type windowScale struct {
		kind       uint8
		length     uint8
		shiftCount uint8
	}
	w := &windowScale{
		kind:       0x03,
		length:     0x03,
		shiftCount: 0x07,
	}
	buf.WriteByte(w.kind)
	buf.WriteByte(w.length)
	buf.WriteByte(w.shiftCount)

	return buf.Bytes()
}
