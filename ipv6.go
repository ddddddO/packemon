package packemon

import (
	"bytes"
	"encoding/binary"
	"net"
)

// rfc: https://datatracker.ietf.org/doc/html/rfc8200#page-6
// https://atmarkit.itmedia.co.jp/ait/articles/1201/05/news113.html
// ↑ によると、「TrafficClass」の前半4bitに拡張ヘッダ（Option）までの長さ入ってるっぽいけど
// https://datatracker.ietf.org/doc/html/rfc8200#section-4 によると、「NextHeader」の種類ごとに、拡張ヘッダー（Option）があるかどうかみたいなのがわかるっぽい？
// ちなみに、NextHeader は、IPv4 の Protocol と同じ値みたい
type IPv6 struct {
	Version       uint8 // 4bit
	TrafficClass  uint8
	FlowLabel     uint32 // 20bit
	PayloadLength uint16
	NextHeader    uint8
	HopLimit      uint8
	SrcAddr       []uint8
	DstAddr       []uint8

	Option []uint8

	Data []byte
}

func NewIPv6(protocol uint8, srcAddr []uint8, dstAddr []uint8) *IPv6 {
	return &IPv6{
		Version:       0x06,
		TrafficClass:  0x00,
		FlowLabel:     0x00000,
		PayloadLength: 0x0000,
		NextHeader:    protocol,
		HopLimit:      0x40,
		SrcAddr:       srcAddr,
		DstAddr:       dstAddr,
	}
}

func ParsedIPv6(payload []byte) *IPv6 {
	return &IPv6{
		Version:      payload[0] >> 4,
		TrafficClass: payload[0]<<4 | payload[1]>>4,
		FlowLabel:    uint32(payload[1]<<4>>4)<<16 | uint32(payload[2])<<8 | uint32(payload[3]),
		// FlowLabel:    binary.BigEndian.Uint32(payload[1] << 4 | payload[2:4]),
		PayloadLength: binary.BigEndian.Uint16(payload[4:6]),
		NextHeader:    payload[6],
		HopLimit:      payload[7],
		SrcAddr:       payload[8:24],
		DstAddr:       payload[24:40],

		// TODO: 拡張ヘッダ付く場合あるため、それを除かないとダメ
		Data: payload[40:],
	}
}

// TODO: IPv4 と同じものは、IPv4_PROTO_HOGE 使っていいかも
const (
	IPv6_NEXT_HEADER_TCP    = IPv4_PROTO_TCP
	IPv6_NEXT_HEADER_UDP    = IPv4_PROTO_UDP
	IPv6_NEXT_HEADER_ICMPv6 = 0x3a
)

func (i *IPv6) StrSrcIPAddr() string {
	return uintsToStrIPv6Addr(i.SrcAddr)
}

func (i *IPv6) StrDstIPAddr() string {
	return uintsToStrIPv6Addr(i.DstAddr)
}

func uintsToStrIPv6Addr(byteAddr []uint8) string {
	ipv6Addr := net.IP(byteAddr)
	return ipv6Addr.To16().String()
}

func (i *IPv6) Bytes() []byte {
	buf := &bytes.Buffer{}

	buf.WriteByte(i.Version<<4 | i.TrafficClass>>4)
	buf.WriteByte(i.TrafficClass<<4 | uint8(i.FlowLabel>>16))                // FlowLabel の20bitから4bit取得
	WriteUint16(buf, uint16(i.FlowLabel&0b00000000000000001111111111111111)) // FlowLabel の20bitから4bitあたまはいらない
	WriteUint16(buf, i.PayloadLength)
	buf.WriteByte(i.NextHeader)
	buf.WriteByte(i.HopLimit)
	buf.Write(i.SrcAddr)
	buf.Write(i.DstAddr)
	buf.Write(i.Option)
	buf.Write(i.Data)

	return buf.Bytes()
}

// 上位レイヤのチェックサムを求めるための
// ref: https://datatracker.ietf.org/doc/html/rfc8200#section-8.1
func (i *IPv6) PseudoHeader(upperLayerLength uint32) []byte {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, i.SrcAddr)
	binary.Write(buf, binary.BigEndian, i.DstAddr)
	WriteUint32(buf, upperLayerLength)
	WriteUint32(buf, uint32(i.NextHeader))
	return buf.Bytes()
}
