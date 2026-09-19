package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverUDP(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcUDPChecksum bool,
	checkedCalcUDPLength bool,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if checkedCalcUDPChecksum {
		s.packets.udp.Checksum = 0x0000
	}
	s.packets.udp.Data = upperLayerPacket
	if checkedCalcUDPLength {
		s.packets.udp.Len()
	}
	ethernetFrame := &packemon.EthernetFrame{
		Header: s.packets.ethernet,
	}

	switch selectedL3 {
	case "":
		ethernetFrame.Data = s.packets.udp.Bytes()
		return s.sendFn(ethernetFrame)
	case "IPv4":
		if checkedCalcUDPChecksum {
			s.packets.udp.CalculateChecksum(s.packets.ipv4)
		}
		return s.sendOverIPv4(ctx, s.packets.udp.Bytes(), ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "IPv6":
		if checkedCalcUDPChecksum {
			s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
		}
		return s.sendOverIPv6(ctx, s.packets.udp.Bytes(), ethernetFrame, checkedCalcIPv6PayloadLength)
	case "ARP":
		return fmt.Errorf("unsupported under ARP")
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL3)
	}
}
