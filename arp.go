package packemon

import (
	"bytes"
	"encoding/binary"
)

const ARP_HARDWARE_TYPE_THERNET = 0x0001

const ARP_PROTO_TYPE_IPv4 = 0x0800

const (
	ARP_OPERATION_CODE_REQUEST = 0x0001
	ARP_OPERATION_CODE_REPLY   = 0x0002
)

// https://ja.wikipedia.org/wiki/Address_Resolution_Protocol#%E3%83%91%E3%82%B1%E3%83%83%E3%83%88%E6%A7%8B%E9%80%A0
// https://beginners-network.com/supplement/arp_packet_format.html
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
	WriteUint16(buf, a.HardwareType)
	WriteUint16(buf, a.ProtocolType)
	buf.WriteByte(a.HardwareAddrLength)
	buf.WriteByte(a.ProtocolLength)
	WriteUint16(buf, a.Operation)
	buf.Write(a.SenderHardwareAddr[:])
	WriteUint32(buf, a.SenderIPAddr)
	buf.Write(a.TargetHardwareAddr[:])
	WriteUint32(buf, a.TargetIPAddr)
	return buf.Bytes()
}

func ParsedARP(payload []byte) *ARP {
	return &ARP{
		HardwareType:       binary.BigEndian.Uint16(payload[0:2]),
		ProtocolType:       binary.BigEndian.Uint16(payload[2:4]),
		HardwareAddrLength: payload[4],
		ProtocolLength:     payload[5],
		Operation:          binary.BigEndian.Uint16(payload[6:8]),

		SenderHardwareAddr: HardwareAddr(payload[8:14]),
		SenderIPAddr:       binary.BigEndian.Uint32(payload[14:18]),

		TargetHardwareAddr: HardwareAddr(payload[18:24]),
		TargetIPAddr:       binary.BigEndian.Uint32(payload[24:28]),
	}
}

func NewARPRequest(sMACAdder HardwareAddr, sIPAddr uint32, tMACAddr HardwareAddr, tIPAddr uint32) *ARP {
	return &ARP{
		HardwareType:       ARP_HARDWARE_TYPE_THERNET,
		ProtocolType:       ARP_PROTO_TYPE_IPv4,
		HardwareAddrLength: 0x06, // イーサネットは6固定
		ProtocolLength:     0x04, // IPv4は4固定
		Operation:          ARP_OPERATION_CODE_REQUEST,

		SenderHardwareAddr: sMACAdder,
		SenderIPAddr:       sIPAddr,
		TargetHardwareAddr: tMACAddr,
		TargetIPAddr:       tIPAddr,
	}
}

func NewARPReply(sMACAdder HardwareAddr, sIPAddr uint32, tMACAddr HardwareAddr, tIPAddr uint32) *ARP {
	return &ARP{
		HardwareType:       ARP_HARDWARE_TYPE_THERNET,
		ProtocolType:       ARP_PROTO_TYPE_IPv4,
		HardwareAddrLength: 0x06,
		ProtocolLength:     0x04,
		Operation:          ARP_OPERATION_CODE_REPLY,

		SenderHardwareAddr: sMACAdder,
		SenderIPAddr:       sIPAddr,
		TargetHardwareAddr: tMACAddr,
		TargetIPAddr:       tIPAddr,
	}
}
