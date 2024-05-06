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
	IPAdder    string // refactor

	PassiveCh chan Passive
}

func NewNetworkInterface(nwInterface string) (*NetworkInterface, error) {
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

	ipAddrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	ipAddr := strings.Split(ipAddrs[0].String(), "/")[0]

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
		IPAdder:    ipAddr,

		PassiveCh: make(chan Passive, 10),
	}, nil
}

func hton(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

func (nw *NetworkInterface) Send(ethernetFrame *EthernetFrame) error {
	return unix.Sendto(nw.Socket, ethernetFrame.Bytes(), 0, &nw.SocketAddr)
}

type Passive struct {
	HTTP          *HTTP
	DNS           *DNS
	TCP           *TCP
	UDP           *UDP
	ICMP          *ICMP
	ARP           *ARP
	IPv4          *IPv4
	EthernetFrame *EthernetFrame
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

				recievedEthernetFrame := &EthernetFrame{
					Header: &EthernetHeader{
						Dst: HardwareAddr(recieved[0:6]),
						Src: HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				HARDWAREADDR_BROADCAST := [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

				switch recievedEthernetFrame.Header.Typ {
				case ETHER_TYPE_ARP:
					switch recievedEthernetFrame.Header.Dst {
					case HardwareAddr(nw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						arp := &ARP{
							HardwareType:       [2]uint8(recievedEthernetFrame.Data[0:2]),
							ProtocolType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
							HardwareAddrLength: recievedEthernetFrame.Data[4],
							ProtocolLength:     recievedEthernetFrame.Data[5],
							Operation:          [2]uint8(recievedEthernetFrame.Data[6:8]),

							SenderHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[8:14]),
							SenderIPAddr:       [4]uint8(recievedEthernetFrame.Data[14:18]),

							TargetHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[18:24]),
							TargetIPAddr:       [4]uint8(recievedEthernetFrame.Data[24:28]),
						}

						nw.PassiveCh <- Passive{
							EthernetFrame: recievedEthernetFrame,
							ARP:           arp,
						}
					}
				case ETHER_TYPE_IPv4:
					switch recievedEthernetFrame.Header.Dst {
					case HardwareAddr(nw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						ipv4 := &IPv4{
							Version:        recievedEthernetFrame.Data[0] >> 4,
							Ihl:            recievedEthernetFrame.Data[0] << 4 >> 4,
							Tos:            recievedEthernetFrame.Data[1],
							TotalLength:    binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
							Identification: binary.BigEndian.Uint16(recievedEthernetFrame.Data[4:6]),
							Flags:          recievedEthernetFrame.Data[6],
							FragmentOffset: binary.BigEndian.Uint16(recievedEthernetFrame.Data[6:8]),
							Ttl:            recievedEthernetFrame.Data[8],
							Protocol:       recievedEthernetFrame.Data[9],
							HeaderChecksum: binary.BigEndian.Uint16(recievedEthernetFrame.Data[10:12]),
							SrcAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.Data[12:16]),
							DstAddr:        binary.BigEndian.Uint32(recievedEthernetFrame.Data[16:20]),
						}

						ipOfEth0, err := strIPToBytes(nw.IPAdder)
						if err != nil {
							return err
						}
						switch ipv4.DstAddr {
						case binary.BigEndian.Uint32(ipOfEth0):
							nw.PassiveCh <- Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
							}
						}
					}
				}
			}
		}
	}

	return nil
}

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
