package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverICMPv6(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Timestamp bool,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	// TODO: sender_over_l4_icmpv4.go と揃えた方が良い？
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6.Data = upperLayerPacket
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6.Header.Checksum = 0x0
		s.packets.icmpv6.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6.Bytes(),
		)
	}

	ethernetFrame := &packemon.EthernetFrame{
		Header: s.packets.ethernet,
	}

	switch selectedL3 {
	case "IPv4":
		return s.sendOverIPv4(ctx, s.packets.icmpv6.Bytes(), ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "IPv6":
		return s.sendOverIPv6(ctx, s.packets.icmpv6.Bytes(), ethernetFrame, checkedCalcIPv6PayloadLength)
	case "ARP":
		return fmt.Errorf("unsupported under ARP")
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL3)
	}
}
