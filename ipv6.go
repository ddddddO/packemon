package packemon

// https://atmarkit.itmedia.co.jp/ait/articles/1201/05/news113.html
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

func ParsedIPv6(payload []byte) *IPv6 {
	return &IPv6{
		Version:      payload[0] >> 4,
		TrafficClass: payload[0]<<4 | payload[1]>>4,
		// FlowLabel: ,
		// PayloadLength: ,
		NextHeader: payload[6],
		HopLimit:   payload[7],
		SrcAddr:    payload[8:24],
		DstAddr:    payload[24:40],
	}
}

const (
	IPv6_NEXT_HEADER_UDP    = 0x11
	IPv6_NEXT_HEADER_ICMPv6 = 0x3a
)
