package generator

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL4(ctx context.Context, selectedL4 string, selectedL3 string) error {
	switch selectedL4 {
	case "ICMP":
		// TODO: timestamp関数化
		s.packets.icmpv4.Data = func() []byte {
			now := time.Now().Unix()
			b := make([]byte, 4)
			binary.LittleEndian.PutUint32(b, uint32(now))
			return binary.LittleEndian.AppendUint32(b, 0x00000000)
		}()
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv4.Checksum = 0x0
		s.packets.icmpv4.Checksum = func() uint16 {
			b := make([]byte, 2)
			binary.LittleEndian.PutUint16(b, s.packets.icmpv4.CalculateChecksum())
			return binary.BigEndian.Uint16(b)
		}()

		switch selectedL3 {
		case "":
		case "IPv4":
			s.packets.ipv4.Data = s.packets.icmpv4.Bytes()
			s.packets.ipv4.CalculateTotalLength()
			// 前回Send分が残ってると計算誤るため
			s.packets.ipv4.HeaderChecksum = 0x0
			s.packets.ipv4.CalculateChecksum()
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
		s.packets.udp.Checksum = 0x0000
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
			s.packets.ipv4.Data = s.packets.udp.Bytes()
			s.packets.ipv4.CalculateTotalLength()
			// 前回Send分が残ってると計算誤るため
			s.packets.ipv4.HeaderChecksum = 0x0
			s.packets.ipv4.CalculateChecksum()
			ethernetFrame.Data = s.packets.ipv4.Bytes()
			return s.sendFn(ethernetFrame)
		case "IPv6":
			s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
			s.packets.ipv6.Data = s.packets.udp.Bytes()
			s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
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
			s.packets.tcp.Checksum = 0x0000
			s.packets.tcp.Data = []byte{} // 前回分の TCP より上のデータをクリア
			ethernetFrame := &packemon.EthernetFrame{
				Header: s.packets.ethernet,
			}

			switch selectedL3 {
			case "":
				ethernetFrame.Data = s.packets.tcp.Bytes()
				return s.sendFn(ethernetFrame)
			case "IPv4":
				s.packets.tcp.CalculateChecksum(s.packets.ipv4)
				s.packets.ipv4.Data = s.packets.tcp.Bytes()
				s.packets.ipv4.CalculateTotalLength()
				// 前回Send分が残ってると計算誤るため
				s.packets.ipv4.HeaderChecksum = 0x0
				s.packets.ipv4.CalculateChecksum()
				ethernetFrame.Data = s.packets.ipv4.Bytes()
				return s.sendFn(ethernetFrame)
			case "IPv6":
				s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
				s.packets.ipv6.Data = s.packets.tcp.Bytes()
				s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
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
