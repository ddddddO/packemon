package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL7(ctx context.Context, selectedL7, selectedL5_6, selectedL4, selectedL3 string) error {
	switch selectedL7 {
	case "DNS":
		switch selectedL5_6 {
		case "":
			switch selectedL4 {
			case "":
				return fmt.Errorf("not implemented under protocol: %s", selectedL4)
			case "UDP":
				if checkedCalcUDPChecksum {
					s.packets.udp.Checksum = 0x0000
				}
				s.packets.udp.Data = s.packets.dns.Bytes()
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
					s.packets.ipv4.Data = s.packets.udp.Bytes()
					s.packets.ipv4.CalculateTotalLength()
					// 前回Send分が残ってると計算誤るため
					s.packets.ipv4.HeaderChecksum = 0x0
					s.packets.ipv4.CalculateChecksum()
					ethernetFrame.Data = s.packets.ipv4.Bytes()
					return s.sendFn(ethernetFrame)
				case "IPv6":
					if checkedCalcUDPChecksum {
						s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
					}
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
							s.packets.dns.Bytes(),
						)
					case "IPv6":
						return packemon.EstablishConnectionAndSendPayloadXxxForIPv6(
							ctx,
							DEFAULT_NW_INTERFACE,
							s.packets.ethernet,
							s.packets.ipv6,
							s.packets.tcp,
							s.packets.dns.Bytes(),
						)
					case "ARP":
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					default:
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					}
				} else {
					s.packets.tcp.Checksum = 0x0000
					s.packets.tcp.Data = s.packets.dns.Bytes()
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
		case "TLSv1.2":
			// TODO:
			return fmt.Errorf("not implemetende under protocol: %s", selectedL5_6)
		default:
			return fmt.Errorf("unsupported under protocol: %s", selectedL5_6)
		}

	case "HTTP":
		switch selectedL5_6 {
		case "":
			switch selectedL4 {
			case "":
				return fmt.Errorf("not implemented under protocol: %s", selectedL4)
			case "UDP":
				// TODO:
				return fmt.Errorf("unsupported under protocol: %s", selectedL4)
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
							s.packets.http.Bytes(),
						)
					case "IPv6":
						return packemon.EstablishConnectionAndSendPayloadXxxForIPv6(
							ctx,
							DEFAULT_NW_INTERFACE,
							s.packets.ethernet,
							s.packets.ipv6,
							s.packets.tcp,
							s.packets.http.Bytes(),
						)
					case "ARP":
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					default:
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					}
				} else {
					s.packets.tcp.Checksum = 0x0000
					s.packets.tcp.Data = s.packets.http.Bytes()
					ethernetFrame := &packemon.EthernetFrame{
						Header: s.packets.ethernet,
					}

					switch selectedL3 {
					case "":
						return fmt.Errorf("not implemented")
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
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					default:
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					}
				}
			default:
				return fmt.Errorf("not implemented under protocol: %s", selectedL4)
			}
		case "TLSv1.2":
			switch selectedL4 {
			case "TCP":
				if doTCP3wayHandshake {
					switch selectedL3 {
					case "":
						return fmt.Errorf("not implemented")
					case "IPv4":
						if doCustomOfTLSv12 {
							return packemon.EstablishTCPTLSv1_2AndSendPayload_CustomImpl(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						} else {
							return packemon.EstablishTCPTLSv1_2AndSendPayload(
								ctx,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						}
					case "IPv6":
						if doCustomOfTLSv12 {
							return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6_CustomImpl(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv6,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						} else {
							return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6(
								ctx,
								s.packets.ipv6,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						}
					case "ARP":
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					default:
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					}
				} else {
					return fmt.Errorf("require tcp 3way handshake")
				}
			}

			return fmt.Errorf("not implemtented")
		case "TLSv1.3":
			switch selectedL4 {
			case "TCP":
				if doTCP3wayHandshake {
					switch selectedL3 {
					case "":
						return fmt.Errorf("not implemented")
					case "IPv4":
						if doCustomOfTLSv13 {
							return packemon.EstablishTCPTLSv1_3AndSendPayload_CustomImpl(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						} else {
							return packemon.EstablishTCPTLSv1_3AndSendPayload(
								ctx,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						}
					case "IPv6":
						return fmt.Errorf("not implemtented")
						// if doCustomOfTLSv13 {}
						// return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6(
						// 	ctx,
						// 	DEFAULT_NW_INTERFACE,
						// 	s.packets.ethernet,
						// 	s.packets.ipv6,
						// 	s.packets.tcp,
						// 	s.packets.http.Bytes(),
						// )
					case "ARP":
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					default:
						return fmt.Errorf("unsupported under protocol: %s", selectedL3)
					}
				} else {
					return fmt.Errorf("require tcp 3way handshake")
				}
			}

			return fmt.Errorf("not implemtented")

		case "QUIC":
			switch selectedL4 {
			case "UDP":
				switch selectedL3 {
				case "":
					return fmt.Errorf("not implemented")
				case "IPv4":
					return packemon.SendUDP_QUIC_HTTP_Payload(
						ctx,
						s.packets.ipv4,
						s.packets.udp,
						s.packets.quic,
						s.packets.http,
					)
				case "IPv6":
					return packemon.SendUDP_QUIC_HTTP_PayloadForIPv6(
						ctx,
						s.packets.ipv6,
						s.packets.udp,
						s.packets.quic,
						s.packets.http,
					)
				default:
					return fmt.Errorf("unsupported under protocol: %s", selectedL3)
				}
			}
			return fmt.Errorf("not implemtented")
		}
		return fmt.Errorf("not implemtented")

	default:
		return fmt.Errorf("unsupported protocol: %s", selectedL7)
	}
}
