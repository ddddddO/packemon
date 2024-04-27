package main

import (
	"bytes"
	"encoding/binary"
)

// https://ja.wikipedia.org/wiki/Address_Resolution_Protocol#%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E6%A7%8B%E9%80%A0
type arp struct {
	hardwareType       [2]uint8
	protocolType       uint16
	hardwareAddrLength uint8
	protocolLength     uint8
	operation          [2]uint8

	srcHardwareAddr hardwareAddr
	srcIPAddr       [4]uint8

	dstHardwareAddr hardwareAddr
	dstIPAddr       [4]uint8
}

func (a *arp) toBytes() []byte {
	var buf bytes.Buffer
	buf.Write(a.hardwareType[:])

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, a.protocolType)
	buf.Write(b)

	buf.WriteByte(a.hardwareAddrLength)
	buf.WriteByte(a.protocolLength)
	buf.Write(a.operation[:])
	buf.Write(a.srcHardwareAddr[:])
	buf.Write(a.srcIPAddr[:])
	buf.Write(a.dstHardwareAddr[:])
	buf.Write(a.dstIPAddr[:])
	return buf.Bytes()
}

func newARP() *arp {
	return &arp{
		hardwareType:       [2]byte{0x00, 0x01},
		protocolType:       ETHER_TYPE_IP,
		hardwareAddrLength: 0x06,
		protocolLength:     0x04,
		operation:          [2]byte{0x00, 0x01},

		srcHardwareAddr: [6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xff},
		srcIPAddr:       [4]byte{0xac, 0x17, 0xf2, 0x4e},

		dstHardwareAddr: [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		dstIPAddr:       [4]byte{0x08, 0x08, 0x08, 0x08},
	}
}