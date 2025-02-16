package tui

import (
	"context"
	"encoding/binary"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/ddddddO/packemon"
)

type sender struct {
	selectedProtocolByLayer map[string]string
	packets                 *packets
	sendFn                  func(*packemon.EthernetFrame) error
}

func newSender(packets *packets, sendFn func(*packemon.EthernetFrame) error) *sender {
	selectedProtocolByLayer := map[string]string{}
	selectedProtocolByLayer["L7"] = "DNS"
	selectedProtocolByLayer["L5/6"] = ""
	selectedProtocolByLayer["L4"] = "UDP"
	selectedProtocolByLayer["L3"] = "IPv4"
	selectedProtocolByLayer["L2"] = "Ethernet"

	return &sender{
		selectedProtocolByLayer: selectedProtocolByLayer,
		packets:                 packets,
		sendFn:                  sendFn,
	}
}

func (s *sender) sendLayer2(ctx context.Context) error {
	return s.send(ctx, "L2")
}

func (s *sender) sendLayer3(ctx context.Context) error {
	return s.send(ctx, "L3")
}

func (s *sender) sendLayer4(ctx context.Context) error {
	return s.send(ctx, "L4")
}

func (s *sender) sendLayer7(ctx context.Context) error {
	return s.send(ctx, "L7")
}

const TIMEOUT = 5000 * time.Millisecond

func (s *sender) send(ctx context.Context, currentLayer string) (err error) {
	defer func() {
		if e := recover(); e != nil {
			trace := debug.Stack()
			err = fmt.Errorf("Panic!!\n%v\nstack trace\n%s\n", e, string(trace))
		}
	}()

	// selectedL2 := s.selectedProtocolByLayer["L2"] // 今、固定でイーサネットだからコメントアウト
	selectedL3 := s.selectedProtocolByLayer["L3"]
	selectedL4 := s.selectedProtocolByLayer["L4"]
	selectedL5_6 := s.selectedProtocolByLayer["L5/6"]
	selectedL7 := s.selectedProtocolByLayer["L7"]

	switch currentLayer {
	case "L2":
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
		})
	case "L3":
		dataL3 := []byte{}
		switch selectedL3 {
		case "ARP":
			dataL3 = s.packets.arp.Bytes()
		case "IPv4":
			s.packets.ipv4.Data = []byte{} // 前回分の IPv4 より上のデータをクリア
			dataL3 = s.packets.ipv4.Bytes()
		case "IPv6":
			s.packets.ipv6.Data = []byte{} // 前回分の IPv6 より上のデータをクリア
			dataL3 = s.packets.ipv6.Bytes()
		default:
			return fmt.Errorf("not implemented form")
		}
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   dataL3,
		})
	case "L4":
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
			case "IPv6":
				s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
				s.packets.ipv6.Data = s.packets.udp.Bytes()
				s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
				ethernetFrame.Data = s.packets.ipv6.Bytes()
			case "ARP":
				return fmt.Errorf("unsupported under ARP")
			default:
				return fmt.Errorf("not implemented under protocol: %s", selectedL3)
			}

			return s.sendFn(ethernetFrame)
		case "TCP":
			s.packets.tcp.Checksum = 0x0000
			s.packets.tcp.Data = []byte{} // 前回分の TCP より上のデータをクリア
			ethernetFrame := &packemon.EthernetFrame{
				Header: s.packets.ethernet,
			}

			switch selectedL3 {
			case "":
				ethernetFrame.Data = s.packets.tcp.Bytes()
			case "IPv4":
				s.packets.tcp.CalculateChecksum(s.packets.ipv4)
				s.packets.ipv4.Data = s.packets.tcp.Bytes()
				s.packets.ipv4.CalculateTotalLength()
				// 前回Send分が残ってると計算誤るため
				s.packets.ipv4.HeaderChecksum = 0x0
				s.packets.ipv4.CalculateChecksum()
				ethernetFrame.Data = s.packets.ipv4.Bytes()
			case "IPv6":
				s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
				s.packets.ipv6.Data = s.packets.tcp.Bytes()
				s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
				ethernetFrame.Data = s.packets.ipv6.Bytes()
			case "ARP":
				return fmt.Errorf("unsupported under ARP")
			default:
				return fmt.Errorf("not implemented under protocol: %s", selectedL3)
			}

			return s.sendFn(ethernetFrame)
		}
	case "L5/6":
		return fmt.Errorf("not implemented layer")
	case "L7":
		switch selectedL7 {
		case "DNS":
			switch selectedL5_6 {
			case "":
				switch selectedL4 {
				case "":
					return fmt.Errorf("not implemented under protocol: %s", selectedL4)
				case "UDP":
					s.packets.udp.Checksum = 0x0000
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
					case "IPv4":
						s.packets.ipv4.Data = s.packets.udp.Bytes()
						s.packets.ipv4.CalculateTotalLength()
						// 前回Send分が残ってると計算誤るため
						s.packets.ipv4.HeaderChecksum = 0x0
						s.packets.ipv4.CalculateChecksum()
						ethernetFrame.Data = s.packets.ipv4.Bytes()
					case "IPv6":
						s.packets.udp.CalculateChecksumForIPv6(s.packets.ipv6)
						s.packets.ipv6.Data = s.packets.udp.Bytes()
						s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
						ethernetFrame.Data = s.packets.ipv6.Bytes()
					case "ARP":
						return fmt.Errorf("unsupported under ARP")
					default:
						return fmt.Errorf("not implemented under protocol: %s", selectedL3)
					}

					return s.sendFn(ethernetFrame)
				case "TCP":
					if do3wayHandshakeForDNS {
						switch selectedL3 {
						case "":
							return fmt.Errorf("not implemented")
						case "IPv4":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

							return packemon.EstablishConnectionAndSendPayloadXxx(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.dns.Bytes(),
							)
						case "IPv6":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

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
						case "IPv4":
							s.packets.tcp.CalculateChecksum(s.packets.ipv4)
							s.packets.ipv4.Data = s.packets.tcp.Bytes()
							s.packets.ipv4.CalculateTotalLength()
							// 前回Send分が残ってると計算誤るため
							s.packets.ipv4.HeaderChecksum = 0x0
							s.packets.ipv4.CalculateChecksum()
							ethernetFrame.Data = s.packets.ipv4.Bytes()
						case "IPv6":
							s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
							s.packets.ipv6.Data = s.packets.tcp.Bytes()
							s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
							ethernetFrame.Data = s.packets.ipv6.Bytes()
						case "ARP":
							return fmt.Errorf("unsupported under ARP")
						default:
							return fmt.Errorf("not implemented under protocol: %s", selectedL3)
						}

						return s.sendFn(ethernetFrame)
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
					if do3wayHandshakeForHTTP {
						switch selectedL3 {
						case "":
							return fmt.Errorf("not implemented")
						case "IPv4":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

							return packemon.EstablishConnectionAndSendPayloadXxx(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						case "IPv6":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

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
						case "IPv6":
							s.packets.tcp.CalculateChecksumForIPv6(s.packets.ipv6)
							s.packets.ipv6.Data = s.packets.tcp.Bytes()
							s.packets.ipv6.PayloadLength = uint16(len(s.packets.ipv6.Data))
							ethernetFrame.Data = s.packets.ipv6.Bytes()
						case "ARP":
							return fmt.Errorf("unsupported under protocol: %s", selectedL3)
						default:
							return fmt.Errorf("unsupported under protocol: %s", selectedL3)
						}

						return s.sendFn(ethernetFrame)
					}
				default:
					return fmt.Errorf("not implemented under protocol: %s", selectedL4)
				}
			case "TLSv1.2":
				switch selectedL4 {
				case "TCP":
					if do3wayHandshakeForHTTP {
						switch selectedL3 {
						case "":
							return fmt.Errorf("not implemented")
						case "IPv4":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

							return packemon.EstablishTCPTLSv1_2AndSendPayload(
								ctx,
								DEFAULT_NW_INTERFACE,
								s.packets.ethernet,
								s.packets.ipv4,
								s.packets.tcp,
								s.packets.http.Bytes(),
							)
						case "IPv6":
							ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT)
							defer cancel()

							return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6(
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
						return fmt.Errorf("require tcp 3way handshake")
					}
				}
				return fmt.Errorf("not implemtented")
			}
		default:
			return fmt.Errorf("unsupported protocol: %s", selectedL7)
		}
	}

	return fmt.Errorf("unsupported layer")
}
