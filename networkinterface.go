package packemon

import (
	"encoding/binary"
	"errors"
	"net"
	"strconv"
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

	ipAddr, err := strIPToBytes(strings.Split(ipAddrs[0].String(), "/")[0])
	if err != nil {
		return nil, err
	}

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

func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (nw *NetworkInterface) Send(ethernetFrame *EthernetFrame) error {
	return unix.Sendto(nw.Socket, ethernetFrame.Bytes(), 0, &nw.SocketAddr)
}

func (nw *NetworkInterface) Recieve() error {
	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	if err := unix.EpollCtl(
		epollfd,
		unix.EPOLL_CTL_ADD,
		nw.Socket,
		&unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(nw.Socket),
		},
	); err != nil {
		return err
	}

	events := make([]unix.EpollEvent, 10)
	for {
		fds, err := unix.EpollWait(epollfd, events, -1)
		if err != nil {
			return err
		}

		for i := 0; i < fds; i++ {
			if events[i].Fd == int32(nw.Socket) {
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

	return nil
}

func (nw *NetworkInterface) Close() error {
	return unix.Close(nw.Socket)
}

// stringのIPv4アドレスをbytesに変換
func strIPToBytes(s string) ([]byte, error) {
	b := make([]byte, 4)
	src := strings.Split(s, ".")

	for i := range src {
		if len(src[i]) == 0 {
			continue
		}
		ip, err := strconv.ParseUint(src[i], 10, 8)
		if err != nil {
			return nil, err
		}
		b[i] = byte(ip)
	}
	return b, nil
}

func ParsedPacket(recieved []byte) *Passive {
	ethernetFrame := ParsedEthernetFrame(recieved)

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

			switch tcp.DstPort {
			case PORT_HTTP:
				if tcp.Flags == TCP_FLAGS_PSH_ACK {
					passive := &Passive{
						EthernetFrame: ethernetFrame,
						IPv4:          ipv4,
						TCP:           tcp,
					}
					if http := ParsedHTTPRequest(tcp.Data); http != nil {
						passive.HTTP = http
					}

					return passive
				}

				return &Passive{
					EthernetFrame: ethernetFrame,
					IPv4:          ipv4,
					TCP:           tcp,
				}
			}

			switch tcp.SrcPort {
			case PORT_HTTP:
				if tcp.Flags == TCP_FLAGS_FIN_PSH_ACK || tcp.Flags == TCP_FLAGS_PSH_ACK {
					passive := &Passive{
						EthernetFrame: ethernetFrame,
						IPv4:          ipv4,
						TCP:           tcp,
					}
					if httpRes := ParsedHTTPResponse(tcp.Data); httpRes != nil {
						passive.HTTPRes = httpRes
					}

					return passive
				}
			}

			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
				TCP:           tcp,
			}

		case IPv4_PROTO_UDP:
			udp := ParsedUDP(ipv4.Data)

			// DNS以外は一旦udpまでのみviewする
			if udp.DstPort != PORT_DNS && udp.SrcPort != PORT_DNS {
				return &Passive{
					EthernetFrame: ethernetFrame,
					IPv4:          ipv4,
					UDP:           udp,
				}
			}

			// TODO: 53確かtcpもあったからそれのハンドリング考慮するいつか
			// TODO: nslookup github.com でipv6用のDNSクエリ・レスポンスも返ってきてるのでそれも対応
			//       query.type == AAAA で判別可能
			flags := binary.BigEndian.Uint16(udp.Data[2:4])
			if udp.DstPort == PORT_DNS && flags == DNS_REQUEST {
				dns := ParsedDNSRequest(udp.Data)

				return &Passive{
					EthernetFrame: ethernetFrame,
					IPv4:          ipv4,
					UDP:           udp,
					DNS:           dns,
				}
			}

			if udp.SrcPort == PORT_DNS && flags == DNS_RESPONSE {
				dns := ParsedDNSResponse(udp.Data)

				return &Passive{
					EthernetFrame: ethernetFrame,
					IPv4:          ipv4,
					UDP:           udp,
					DNS:           dns,
				}
			}
		default:
			return &Passive{
				EthernetFrame: ethernetFrame,
				IPv4:          ipv4,
			}
		}
	}

	return &Passive{
		EthernetFrame: ethernetFrame,
	}
}
