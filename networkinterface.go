package packemon

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

type NetworkInterface struct {
	Intf       net.Interface
	Socket     int // file discripter
	SocketAddr unix.SockaddrLinklayer
	IPAdder    string // refactor

	PassiveCh chan Passive
}

func NewNetworkInterface() (*NetworkInterface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var intf net.Interface
	for i := range interfaces {
		if interfaces[i].Name == "eth0" {
			intf = interfaces[i]
		}
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

// TODO: この辺りのsendXxxは、debugのためにあるからinternal/debugとか掘ってそこに置いとくのがいいかも
func (nw *NetworkInterface) SendARPrequest(firsthopMACAddr [6]byte) error {
	arp := NewARP()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_ARP, arp.Bytes())
	return nw.Send(ethernetFrame)
}

func (nw *NetworkInterface) SendICMPechoRequest(firsthopMACAddr [6]byte) error {
	icmp := NewICMP()
	ipv4 := NewIPv4(IPv4_PROTO_ICMP, 0xa32b661d) // dst: 163.43.102.29 = tools.m-bsys.com
	ipv4.Data = icmp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
}

func (nw *NetworkInterface) SendDNSquery(firsthopMACAddr [6]byte) error {
	dns := &DNS{
		TransactionID: 0x1234,
		Flags:         0x0100, // standard query
		Questions:     0x0001,
		AnswerRRs:     0x0000,
		AuthorityRRs:  0x0000,
		AdditionalRRs: 0x0000,
		Queries: &Queries{
			Typ:   0x0001, // A
			Class: 0x0001, // IN
		},
	}
	// dns.domain("github.com")
	dns.Domain("go.dev")
	udp := &UDP{
		SrcPort:  0x0401, // 1025
		DstPort:  0x0035, // 53
		Length:   0x0000,
		Checksum: 0x0000,
	}
	udp.Data = dns.Bytes()
	udp.Len()
	ipv4 := NewIPv4(IPv4_PROTO_UDP, 0x08080808) // 8.8.8.8 = DNSクエリ用
	ipv4.Data = udp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
}

func (nw *NetworkInterface) SendTCPsyn(firsthopMACAddr [6]byte) error {
	tcp := NewTCPSyn()
	ipv4 := NewIPv4(IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.Bytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
}

func (nw *NetworkInterface) SendHTTPget(firsthopMACAddr [6]byte) error {
	http := NewHTTP()
	tcp := NewTCPWithData(http.Bytes())
	ipv4 := NewIPv4(IPv4_PROTO_TCP, 0x88bb0609) // 136.187.6.9 = research.nii.ac.jp
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			var buf bytes.Buffer
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.SrcAddr)
			buf.Write(b)
			b = make([]byte, 4)
			binary.BigEndian.PutUint32(b, ipv4.DstAddr)
			buf.Write(b)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			b = make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(len(tcp.Bytes())))
			buf.Write(b)
			return buf.Bytes()
		}()
		var forTCPChecksum bytes.Buffer
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := HardwareAddr(firsthopMACAddr)
	src := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dst, src, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
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
