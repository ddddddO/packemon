package main

import (
	"bytes"
	"encoding/binary"
	"net"
)

type ethernetFrame struct {
	header *ethernetHeader
	data   []byte
}

func newEthernetFrame(dst hardwareAddr, src net.HardwareAddr, payload []byte) *ethernetFrame {
	return &ethernetFrame{
		header: &ethernetHeader{
			dst: dst,
			src: hardwareAddr(src),
			typ: ETHER_TYPE_ARP,
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

type hardwareAddr [6]uint8

type ethernetHeader struct {
	dst hardwareAddr
	src hardwareAddr
	typ uint16
}

const ETHER_TYPE_IP uint16 = 0x0800
const ETHER_TYPE_ARP uint16 = 0x0806
