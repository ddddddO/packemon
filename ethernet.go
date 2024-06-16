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
	return &EthernetFrame{
		Header: &EthernetHeader{
			Dst: HardwareAddr(b[0:6]),
			Src: HardwareAddr(b[6:12]),
			Typ: binary.BigEndian.Uint16(b[12:14]), // タグVLANだとズレる
		},
		Data: b[14:],
	}
}

func (ef *EthernetFrame) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(ef.Header.Dst[:])
	buf.Write(ef.Header.Src[:])
	WriteUint16(buf, ef.Header.Typ)
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

func (h *HardwareAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", h[0], h[1], h[2], h[3], h[4], h[5])
}

const ETHER_TYPE_IPv4 uint16 = 0x0800
const ETHER_TYPE_IPv6 uint16 = 0x86dd
const ETHER_TYPE_ARP uint16 = 0x0806
