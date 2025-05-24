package packemon

import (
	"context"
	"encoding/binary"
)

func NewNetworkInterface(nwInterface string) (*NetworkInterface, error) {
	return newNetworkInterface(nwInterface)
}

func (nw *NetworkInterface) Send(ethernetFrame *EthernetFrame) error {
	return nw.send(ethernetFrame)
}

func (nw *NetworkInterface) Recieve(ctx context.Context) error {
	return nw.recieve(ctx)
}

func (nw *NetworkInterface) Close() error {
	return nw.close()
}

func ParsedPacket(recieved []byte) (passive *Passive) {
	ethernetFrame := ParsedEthernetFrame(recieved)
	defer func() {
		if e := recover(); e != nil {
			// TODO: なにかしらログ出す
			// log.Printf("Panic!:\n%v\n", e)

			// 一旦生のイーサネットフレームを出しとく
			passive = &Passive{
				EthernetFrame: ethernetFrame,
			}
		}
	}()

	const DEBUG_10443 uint16 = 0x28CB // TODO: 一時的なもの。TLS1.3 を試すための

	switch ethernetFrame.Header.Typ {
	case ETHER_TYPE_ARP:
		arp := ParsedARP(ethernetFrame.Data)

		return &Passive{
			EthernetFrame: ethernetFrame,
			ARP:           arp,
		}

	case ETHER_TYPE_IPv4:
		ipv4 := ParsedIPv4(ethernetFrame.Data)

		switch ipv4.Protocol {
		case IPv4_PROTO_ICMP:
			icmp := ParsedICMP(ipv4.Data)

			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
				ICMP:          icmp,
			}

		case IPv4_PROTO_TCP:
			tcp := ParsedTCP(ipv4.Data)

			passive := &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
				TCP:           tcp,
			}

			switch tcp.DstPort {
			case PORT_HTTP:
				if tcp.Flags == TCP_FLAGS_PSH_ACK {
					if http := ParsedHTTPRequest(tcp.Data); http != nil {
						passive.HTTP = http
					}
				}
				return passive

			case PORT_HTTPS, DEBUG_10443:
				ParsedTLSToPassive(tcp, passive)
				return passive
			}

			switch tcp.SrcPort {
			case PORT_HTTP:
				if tcp.Flags == TCP_FLAGS_FIN_PSH_ACK || tcp.Flags == TCP_FLAGS_PSH_ACK {
					if httpRes := ParsedHTTPResponse(tcp.Data); httpRes != nil {
						passive.HTTPRes = httpRes
					}
				}
				return passive

			case PORT_HTTPS, DEBUG_10443:
				ParsedTLSToPassive(tcp, passive)
				return passive
			}

			return passive

		case IPv4_PROTO_UDP:
			udp := ParsedUDP(ipv4.Data)

			passive := &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
				UDP:           udp,
			}

			// DNS以外は一旦udpまでのみviewする
			if udp.DstPort != PORT_DNS && udp.SrcPort != PORT_DNS {
				return passive
			}

			// TODO: 53確かtcpもあったからそれのハンドリング考慮するいつか
			// TODO: nslookup github.com でipv6用のDNSクエリ・レスポンスも返ってきてるのでそれも対応
			//       query.type == AAAA で判別可能
			flags := binary.BigEndian.Uint16(udp.Data[2:4])
			if udp.DstPort == PORT_DNS && IsDNSRequest(flags) {
				dns := ParsedDNSRequest(udp.Data)
				passive.DNS = dns
				return passive
			}

			if udp.SrcPort == PORT_DNS && IsDNSResponse(flags) {
				dns := ParsedDNSResponse(udp.Data)
				passive.DNS = dns
				return passive
			}

			return passive

		default:
			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
			}
		}
	case ETHER_TYPE_IPv6:
		ipv6 := ParsedIPv6(ethernetFrame.Data)

		switch ipv6.NextHeader {
		case IPv6_NEXT_HEADER_ICMPv6:
			// TODO:
			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv6:          ipv6,
			}
		case IPv6_NEXT_HEADER_UDP:
			udp := ParsedUDP(ipv6.Data)
			passive := &Passive{
				EthernetFrame: ethernetFrame,
				IPv6:          ipv6,
				UDP:           udp,
			}

			// DNS以外は一旦udpまでのみviewする
			if udp.DstPort != PORT_DNS && udp.SrcPort != PORT_DNS {
				return passive
			}

			// TODO: 53確かtcpもあったからそれのハンドリング考慮するいつか
			// TODO: nslookup github.com でipv6用のDNSクエリ・レスポンスも返ってきてるのでそれも対応
			//       query.type == AAAA で判別可能
			flags := binary.BigEndian.Uint16(udp.Data[2:4])
			if udp.DstPort == PORT_DNS && IsDNSRequest(flags) {
				dns := ParsedDNSRequest(udp.Data)
				passive.DNS = dns
				return passive
			}

			if udp.SrcPort == PORT_DNS && IsDNSResponse(flags) {
				dns := ParsedDNSResponse(udp.Data)
				passive.DNS = dns
				return passive
			}

			return passive

		default:
			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv6:          ipv6,
			}
		}
	default:
		return &Passive{
			EthernetFrame: ethernetFrame,
		}
	}
}
