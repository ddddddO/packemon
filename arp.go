package main

import (
	"bytes"
	"encoding/binary"
)

// https://ja.wikipedia.org/wiki/Address_Resolution_Protocol#%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E6%A7%8B%E9%80%A0
type ARP struct {
	HardwareType       [2]uint8
	ProtocolType       uint16
	HardwareAddrLength uint8
	ProtocolLength     uint8
	Operation          [2]uint8

	SenderHardwareAddr hardwareAddr
	SenderIPAddr       [4]uint8

	TargetHardwareAddr hardwareAddr
	TargetIPAddr       [4]uint8
}

func (a *ARP) Bytes() []byte {
	var buf bytes.Buffer
	buf.Write(a.HardwareType[:])

	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, a.ProtocolType)
	buf.Write(b)

	buf.WriteByte(a.HardwareAddrLength)
	buf.WriteByte(a.ProtocolLength)
	buf.Write(a.Operation[:])
	buf.Write(a.SenderHardwareAddr[:])
	buf.Write(a.SenderIPAddr[:])
	buf.Write(a.TargetHardwareAddr[:])
	buf.Write(a.TargetIPAddr[:])
	return buf.Bytes()
}

func NewARP() *ARP {
	return &ARP{
		HardwareType:       [2]byte{0x00, 0x01},
		ProtocolType:       ETHER_TYPE_IPv4,
		HardwareAddrLength: 0x06,
		ProtocolLength:     0x04,
		Operation:          [2]byte{0x00, 0x01},

		SenderHardwareAddr: [6]byte{0x00, 0x15, 0x5d, 0xe6, 0xa9, 0x68},
		SenderIPAddr:       [4]byte{0xac, 0x17, 0xf2, 0x4e},

		TargetHardwareAddr: [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		TargetIPAddr:       [4]byte{0xac, 0x17, 0xf0, 0x01},
	}
}
