package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverTCP(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	doTCP3wayHandshake bool,
	checkedCalcTCPChecksum bool,
	checkedCalcIPv4Checksum bool,
) error {
	if doTCP3wayHandshake {
		switch selectedL3 {
		case "":
			return fmt.Errorf("not implemented")
		case "IPv4":
			return packemon.EstablishConnectionAndSendPayloadXxx(
				ctx,
				DEFAULT_NW_INTERFACE,
				s.packets.ethernet,
				s.packets.ipv4,
				s.packets.tcp,
				upperLayerPacket,
			)
		case "IPv6":
			return packemon.EstablishConnectionAndSendPayloadXxxForIPv6(
				ctx,
				DEFAULT_NW_INTERFACE,
				s.packets.ethernet,
				s.packets.ipv6,
				s.packets.tcp,
				upperLayerPacket,
			)
		case "ARP":
			return fmt.Errorf("unsupported under protocol: %s", selectedL3)
		default:
			return fmt.Errorf("unsupported under protocol: %s", selectedL3)
		}
	} else {
		if checkedCalcTCPChecksum {
			s.packets.tcp.Checksum = 0x0000
		}
		s.packets.tcp.Data = upperLayerPacket
		ethernetFrame := &packemon.EthernetFrame{
			Header: s.packets.ethernet,
		}

		switch selectedL3 {
		case "":
			ethernetFrame.Data = s.packets.tcp.Bytes()
			return s.sendFn(ethernetFrame)
		case "IPv4":
			if checkedCalcTCPChecksum {
				s.packets.tcp.CalculateChecksum(s.packets.ipv4)
			}
			return s.sendOverIPv4(ctx, s.packets.tcp.Bytes(), ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
		case "IPv6":
			if checkedCalcTCPChecksum {
				s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
			}
			return s.sendOverIPv6(ctx, s.packets.tcp.Bytes(), ethernetFrame, checkedCalcIPv6PayloadLength)
		case "ARP":
			return fmt.Errorf("unsupported under ARP")
		default:
			return fmt.Errorf("not implemented under protocol: %s", selectedL3)
		}
	}
}
