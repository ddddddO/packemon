package main

import (
	"bytes"
	"encoding/binary"
)

func newEthernetFrame(dst hardwareAddr, src hardwareAddr, typ uint16, payload []byte) *ethernetFrame {
	return &ethernetFrame{
		header: &ethernetHeader{
			dst: dst,
			src: src,
			typ: typ,
		},
		data: payload,
	}
}

func (ef *ethernetFrame) toBytes() []byte {
	var buf bytes.Buffer
	buf.Write(ef.header.dst[:])
	buf.Write(ef.header.src[:])

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, ef.header.typ)
	buf.Write(b)

	buf.Write(ef.data)
	return buf.Bytes()
}

type ethernetFrame struct {
	header *ethernetHeader
	data   []byte
}

type ethernetHeader struct {
	dst hardwareAddr
	src hardwareAddr
	typ uint16
}

type hardwareAddr [6]uint8

const ETHER_TYPE_IPv4 uint16 = 0x0800
const ETHER_TYPE_IPv6 uint16 = 0x86dd
const ETHER_TYPE_ARP uint16 = 0x0806
