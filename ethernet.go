package packemon

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

func ParsedEthernetFrame(b []byte) *EthernetFrame {
	eth := &EthernetHeader{
		Dst: HardwareAddr(b[0:6]),
		Src: HardwareAddr(b[6:12]),
		Typ: binary.BigEndian.Uint16(b[12:14]),
	}

	if eth.Typ == ETHER_TYPE_DOT1Q && len(b) >= 18 {
		eth.Dot1QFiels = &EthernetDot1QFields{
			Dot1QFiels: binary.BigEndian.Uint16(b[14:16]),
			Type:       binary.BigEndian.Uint16(b[16:18]),
		}

		if len(b) >= 19 {
			return &EthernetFrame{
				Header: eth,
				Data:   b[18:],
			}
		}
		return &EthernetFrame{
			Header: eth,
		}
	}

	return &EthernetFrame{
		Header: eth,
		Data:   b[14:],
	}
}

func (ef *EthernetFrame) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(ef.Header.Dst[:])
	buf.Write(ef.Header.Src[:])
	WriteUint16(buf, ef.Header.Typ)

	// Generator で、EtherType=DOT1Qを指定したときだけそれ用のフィールドを送信する、仕様
	if ef.Header.Typ == ETHER_TYPE_DOT1Q {
		WriteUint16(buf, ef.Header.Dot1QFiels.Dot1QFiels)
		WriteUint16(buf, ef.Header.Dot1QFiels.Type)
	}

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

	Dot1QFiels *EthernetDot1QFields
}

type EthernetDot1QFields struct {
	Dot1QFiels uint16
	Type       uint16

	// TODO: Dot1QFiels をさらに細分化
	// PriorityCodePoint        uint8  // 3bit
	// CanonicalFormatIndicator uint8  // 1bit
	// VLANID                   uint16 // 12bit
}

type HardwareAddr [6]uint8

func (h *HardwareAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4], h[5])
}

const ETHER_TYPE_IPv4 uint16 = 0x0800
const ETHER_TYPE_IPv6 uint16 = 0x86dd
const ETHER_TYPE_ARP uint16 = 0x0806
const ETHER_TYPE_DOT1Q uint16 = 0x8100 // IEEE 802.1Q, VLAN-tag
