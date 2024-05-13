package packemon

import (
	"bytes"
)

// https://ja.wikipedia.org/wiki/Address_Resolution_Protocol#%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E6%A7%8B%E9%80%A0
type ARP struct {
	HardwareType       uint16
	ProtocolType       uint16
	HardwareAddrLength uint8
	ProtocolLength     uint8
	Operation          uint16

	SenderHardwareAddr HardwareAddr
	SenderIPAddr       uint32

	TargetHardwareAddr HardwareAddr
	TargetIPAddr       uint32
}

func (a *ARP) Bytes() []byte {
	buf := &bytes.Buffer{}
	writeUint16(buf, a.HardwareType)
	writeUint16(buf, a.ProtocolType)
	buf.WriteByte(a.HardwareAddrLength)
	buf.WriteByte(a.ProtocolLength)
	writeUint16(buf, a.Operation)
	buf.Write(a.SenderHardwareAddr[:])
	writeUint32(buf, a.SenderIPAddr)
	buf.Write(a.TargetHardwareAddr[:])
	writeUint32(buf, a.TargetIPAddr)
	return buf.Bytes()
}

func NewARP() *ARP {
	return &ARP{
		HardwareType:       0x0001,
		ProtocolType:       ETHER_TYPE_IPv4,
		HardwareAddrLength: 0x06,
		ProtocolLength:     0x04,
		Operation:          0x0001,

		SenderHardwareAddr: [6]byte{0x00, 0x15, 0x5d, 0xdc, 0x7e, 0xe9},
		SenderIPAddr:       0xac17f24e,

		TargetHardwareAddr: [6]uint8{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		TargetIPAddr:       0xac17f001,
	}
}
