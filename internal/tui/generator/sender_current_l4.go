package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL4(ctx context.Context, selectedL4 string, selectedL3 string) error {
	switch selectedL4 {
	case "ICMP":
		s.packets.icmpv4.Data = []byte{}
		if checkedCalcICMPTimestamp {
			s.packets.icmpv4.Data = s.packets.icmpv4.TimestampForTypeTimestampRequest()
		}
		if checkedCalcICMPChecksum {
			// 前回Send分が残ってると計算誤るため
			s.packets.icmpv4.Checksum = 0x0
			s.packets.icmpv4.CalculateChecksum()
		}

		switch selectedL3 {
		case "":
		case "IPv4":
			s.packets.ipv4.Data = s.packets.icmpv4.Bytes()
			if checkedCalcIPv4TotalLength {
				s.packets.ipv4.CalculateTotalLength()
			}
			if checkedCalcIPv4Checksum {
				// 前回Send分が残ってると計算誤るため
				s.packets.ipv4.HeaderChecksum = 0x0
				s.packets.ipv4.CalculateChecksum()
			}
			ethernetFrame := &packemon.EthernetFrame{
				Header: s.packets.ethernet,
				Data:   s.packets.ipv4.Bytes(),
			}
			return s.sendFn(ethernetFrame)

		case "IPv6":
			return fmt.Errorf("not implemented under protocol: %s", selectedL3)
		case "ARP":
			return fmt.Errorf("unsupported under ARP")
		default:
			return fmt.Errorf("not implemented under protocol: %s", selectedL3)
		}

	case "UDP":
		if checkedCalcUDPChecksum {
			s.packets.udp.Checksum = 0x0000
		}
		s.packets.udp.Data = []byte{} // 前回分の UDP より上のデータをクリア
		if checkedCalcUDPLength {
			s.packets.udp.Len()
		}
		ethernetFrame := &packemon.EthernetFrame{
			Header: s.packets.ethernet,
		}

		switch selectedL3 {
		case "":
			ethernetFrame.Data = s.packets.udp.Bytes()
		case "IPv4":
			if checkedCalcUDPChecksum {
				s.packets.udp.CalculateChecksum(s.packets.ipv4)
			}
			s.packets.ipv4.Data = s.packets.udp.Bytes()
			if checkedCalcIPv4TotalLength {
				s.packets.ipv4.CalculateTotalLength()
			}
			if checkedCalcIPv4Checksum {
				// 前回Send分が残ってると計算誤るため
				s.packets.ipv4.HeaderChecksum = 0x0
				s.packets.ipv4.CalculateChecksum()
			}
			ethernetFrame.Data = s.packets.ipv4.Bytes()
			return s.sendFn(ethernetFrame)
		case "IPv6":
			if checkedCalcUDPChecksum {
				s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
			}
			s.packets.ipv6.Data = s.packets.udp.Bytes()
			if checkedCalcIPv6PayloadLength {
				s.packets.ipv6.CalculatePayloadLength()
			}
			ethernetFrame.Data = s.packets.ipv6.Bytes()
			return s.sendFn(ethernetFrame)
		case "ARP":
			return fmt.Errorf("unsupported under ARP")
		default:
			return fmt.Errorf("not implemented under protocol: %s", selectedL3)
		}
	case "TCP":
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
					nil,
				)
			case "IPv6":
				return packemon.EstablishConnectionAndSendPayloadXxxForIPv6(
					ctx,
					DEFAULT_NW_INTERFACE,
					s.packets.ethernet,
					s.packets.ipv6,
					s.packets.tcp,
					nil,
				)
			case "ARP":
				return fmt.Errorf("unsupported under protocol: %s", selectedL3)
			default:
				return fmt.Errorf("unsupported under protocol: %s", selectedL3)
			}
		} else {
			s.packets.tcp.Data = []byte{} // 前回分の TCP より上のデータをクリア
			if checkedCalcTCPChecksum {
				s.packets.tcp.Checksum = 0x0000
			}
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
				s.packets.ipv4.Data = s.packets.tcp.Bytes()
				if checkedCalcIPv4TotalLength {
					s.packets.ipv4.CalculateTotalLength()
				}
				if checkedCalcIPv4Checksum {
					// 前回Send分が残ってると計算誤るため
					s.packets.ipv4.HeaderChecksum = 0x0
					s.packets.ipv4.CalculateChecksum()
				}
				ethernetFrame.Data = s.packets.ipv4.Bytes()
				return s.sendFn(ethernetFrame)
			case "IPv6":
				if checkedCalcTCPChecksum {
					s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
				}
				s.packets.ipv6.Data = s.packets.tcp.Bytes()
				if checkedCalcIPv6PayloadLength {
					s.packets.ipv6.CalculatePayloadLength()
				}
				ethernetFrame.Data = s.packets.ipv6.Bytes()
				return s.sendFn(ethernetFrame)
			case "ARP":
				return fmt.Errorf("unsupported under ARP")
			default:
				return fmt.Errorf("not implemented under protocol: %s", selectedL3)
			}
		}
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL4)
	}

	return fmt.Errorf("unsupported protocol")
}
