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

	senderHardwareAddr hardwareAddr
	senderIPAddr       [4]uint8

	targetHardwareAddr hardwareAddr
	targetIPAddr       [4]uint8
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
	buf.Write(a.senderHardwareAddr[:])
	buf.Write(a.senderIPAddr[:])
	buf.Write(a.targetHardwareAddr[:])
	buf.Write(a.targetIPAddr[:])
	return buf.Bytes()
}

func newARP() *arp {
	return &arp{
		hardwareType:       [2]byte{0x00, 0x01},
		protocolType:       ETHER_TYPE_IPv4,
		hardwareAddrLength: 0x06,
		protocolLength:     0x04,
		operation:          [2]byte{0x00, 0x01},

		senderHardwareAddr: [6]byte{0x00, 0x15, 0x5d, 0xe6, 0xa9, 0x68},
		senderIPAddr:       [4]byte{0xac, 0x17, 0xf2, 0x4e},

		targetHardwareAddr: [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		targetIPAddr:       [4]byte{0xac, 0x17, 0xf0, 0x01},
	}
}
