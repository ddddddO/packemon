package packemon

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

type NetworkInterface struct {
	Intf       *net.Interface
	Socket     int // file discripter
	SocketAddr unix.SockaddrLinklayer
	IPAdder    uint32

	PassiveCh chan *Passive
}

func NewNetworkInterface(nwInterface string) (*NetworkInterface, error) {
	intf, err := getInterface(nwInterface)
	if err != nil {
		return nil, err
	}
	ipAddrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	if len(ipAddrs) == 0 {
		return nil, errors.New("network interface may not have IP address configured")
	}

	ipAddr, err := StrIPToBytes(strings.Split(ipAddrs[0].String(), "/")[0])
	if err != nil {
		return nil, err
	}

	// https://ja.manpages.org/af_packet/7 のリンク先に、以下コード1行分の説明あり. ためになる.
	// https://github.com/pandax381/seccamp2024 の README にリンクされているスライドもためになる(「KLab Expert Camp 6 - Day3」のとこ).
	// また、上記スライドに各OSで直接Ethernetフレームを送受信する手段についてもヒントあり.
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hton(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	addr := unix.SockaddrLinklayer{
		Protocol: hton(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(sock, &addr); err != nil {
		return nil, err
	}

	return &NetworkInterface{
		Intf:       intf,
		Socket:     sock,
		SocketAddr: addr,
		IPAdder:    binary.BigEndian.Uint32(ipAddr),

		PassiveCh: make(chan *Passive, 100),
	}, nil
}

func getInterface(nwInterface string) (*net.Interface, error) {
	// any で全てのインタフェースを取得しない限り、net.InterfaceByName で取得がいいかもしれない
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var intf *net.Interface
	for i := range interfaces {
		if interfaces[i].Name == nwInterface {
			intf = &interfaces[i]
		}
	}
	if intf == nil {
		return nil, errors.New("specified interface did not exist")
	}

	return intf, nil
}

// host to network. ホストマシンのメモリ上のバイトオーダー(CPUにより異なる. Intel系のCPUはリトルエンディアン)からネットワークへ送信するバイトオーダー(ビッグエンディアン)へ変換するための関数
func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (nw *NetworkInterface) Send(ethernetFrame *EthernetFrame) error {
	return unix.Sendto(nw.Socket, ethernetFrame.Bytes(), 0, &nw.SocketAddr)
}

func (nw *NetworkInterface) Recieve(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			recieved := make([]byte, 1500)
			n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
			if err != nil {
				if n == -1 {
					continue
				}
				return err
			}

			nw.PassiveCh <- ParsedPacket(recieved)
		}
	}
}

func (nw *NetworkInterface) Close() error {
	return unix.Close(nw.Socket)
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
