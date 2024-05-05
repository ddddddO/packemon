package main

import (
	"bytes"
	"encoding/binary"
)

func NewEthernetFrame(dst HardwareAddr, src HardwareAddr, typ uint16, payload []byte) *EthernetFrame {
	return &EthernetFrame{
		Header: &EthernetHeader{
			Dst: dst,
			Src: src,
			Typ: typ,
		},
		Data: payload,
	}
}

func (ef *EthernetFrame) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(ef.Header.Dst[:])
	buf.Write(ef.Header.Src[:])

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, ef.Header.Typ)
	buf.Write(b)

	buf.Write(ef.Data)
	return buf.Bytes()
}

type EthernetFrame struct {
	Header *EthernetHeader
	Data   []byte
}

type EthernetHeader struct {
	Dst HardwareAddr
	Src HardwareAddr
	Typ uint16
}

type HardwareAddr [6]uint8

const ETHER_TYPE_IPv4 uint16 = 0x0800
const ETHER_TYPE_IPv6 uint16 = 0x86dd
const ETHER_TYPE_ARP uint16 = 0x0806
