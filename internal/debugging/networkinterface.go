package debugging

import (
	"bytes"
	"encoding/binary"
	"log"

	"github.com/ddddddO/packemon"
	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

type debugNetworkInterface struct {
	*p.NetworkInterface
}

func NewDebugNetworkInterface(netIF *p.NetworkInterface) *debugNetworkInterface {
	return &debugNetworkInterface{
		NetworkInterface: netIF,
	}
}

func (dnw *debugNetworkInterface) SendARPrequest() error {
	arp := p.NewARP()
	dst := p.HardwareAddr([6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_ARP, arp.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendICMPechoRequest(firsthopMACAddr [6]byte) error {
	icmp := p.NewICMP()
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	ipv4 := p.NewIPv4(p.IPv4_PROTO_ICMP, srcIPAddr, dstIPAddr)
	ipv4.Data = icmp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendDNSquery(firsthopMACAddr [6]byte) error {
	dns := &p.DNS{
		TransactionID: 0x1234,
		Flags:         0x0100, // standard query
		Questions:     0x0001,
		AnswerRRs:     0x0000,
		AuthorityRRs:  0x0000,
		AdditionalRRs: 0x0000,
		Queries: &p.Queries{
			Typ:   0x0001, // A
			Class: 0x0001, // IN
		},
	}
	// dns.domain("github.com")
	dns.Domain("go.dev")
	udp := &p.UDP{
		SrcPort:  0x0401, // 1025
		DstPort:  0x0035, // 53
		Length:   0x0000,
		Checksum: 0x0000,
	}
	udp.Data = dns.Bytes()
	udp.Len()
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0x08080808 // 8.8.8.8 = DNSクエリ用
	ipv4 := p.NewIPv4(p.IPv4_PROTO_UDP, srcIPAddr, dstIPAddr)
	ipv4.Data = udp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendTCPsyn(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0x9e96
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp := p.NewTCPSyn(srcPort)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendTCP3wayhandshake(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0xa003
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	dstMACAddr := p.HardwareAddr(firsthopMACAddr)
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)

	tcp := p.NewTCPSyn(srcPort)
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	if err := dnw.Send(ethernetFrame); err != nil {
		return err
	}

	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	if err := unix.EpollCtl(
		epollfd,
		unix.EPOLL_CTL_ADD,
		dnw.Socket,
		&unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(dnw.Socket),
		},
	); err != nil {
		return err
	}

	events := make([]unix.EpollEvent, 10)
	for {
		log.Println("in outer loop")

		fds, err := unix.EpollWait(epollfd, events, -1)
		if err != nil {
			return err
		}

		for i := 0; i < fds; i++ {
			log.Println("in inner loop")

			if events[i].Fd == int32(dnw.Socket) {
				recieved := make([]byte, 1500)
				n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
				if err != nil {
					if n == -1 {
						continue
					}
					return err
				}

				ethernetFrame := p.ParsedEthernetFrame(recieved)

				switch ethernetFrame.Header.Typ {
				case p.ETHER_TYPE_IPv4:
					ipv4 := p.ParsedIPv4(ethernetFrame.Data)

					switch ipv4.Protocol {
					case p.IPv4_PROTO_TCP:
						tcp := p.ParsedTCP(ipv4.Data)

						switch tcp.DstPort {
						case srcPort: // synパケットの送信元ポート
							if tcp.Flags == p.TCP_FLAGS_SYN_ACK {
								log.Println("passive TCP_FLAGS_SYN_ACK")

								// syn/ackを受け取ったのでack送信
								tcp := p.NewTCPAck(srcPort, tcp.Sequence, tcp.Acknowledgment)
								ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
								tcp.CalculateChecksum(ipv4)

								ipv4.Data = tcp.Bytes()
								ipv4.CalculateTotalLength()
								ipv4.CalculateChecksum()

								ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
								if err := dnw.Send(ethernetFrame); err != nil {
									return err
								}

								if err := dnw.SendHTTPget(srcPort, srcIPAddr, dstIPAddr, firsthopMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
									return err
								}
								continue
							}

							if tcp.Flags == p.TCP_FLAGS_ACK {
								log.Println("passive TCP_FLAGS_ACK")
								continue
							}

							if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
								lineLength := bytes.Index(tcp.Data, []byte{0x0d, 0x0a}) // "\r\n"
								if lineLength == -1 {
									log.Println("-1")
									continue
								}
								log.Println("passive TCP_FLAGS_PSH_ACK")

								// HTTPレスポンス受信
								if tcp.SrcPort == packemon.PORT_HTTP {
									resp := p.ParsedHTTPResponse(tcp.Data)
									log.Printf("%+v\n", resp)

									// そのackを返す
									log.Printf("Length of http resp: %d\n", resp.Len())

									tcp := p.NewTCPAckForPassiveData(srcPort, tcp.Sequence, tcp.Acknowledgment, resp.Len())
									ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
									tcp.CalculateChecksum(ipv4)

									ipv4.Data = tcp.Bytes()
									ipv4.CalculateTotalLength()
									ipv4.CalculateChecksum()

									ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
									if err := dnw.Send(ethernetFrame); err != nil {
										return err
									}

									// 続けてFinAck
									tcp = p.NewTCPFinAck(srcPort, tcp.Sequence, tcp.Acknowledgment)
									ipv4 = p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
									tcp.CalculateChecksum(ipv4)

									ipv4.Data = tcp.Bytes()
									ipv4.CalculateTotalLength()
									ipv4.CalculateChecksum()

									ethernetFrame = p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
									if err := dnw.Send(ethernetFrame); err != nil {
										return err
									}
								}
								continue
							}

							if tcp.Flags == p.TCP_FLAGS_FIN_ACK {
								log.Println("passive TCP_FLAGS_FIN_ACK")

								// それにack
								tcp := p.NewTCPAck(srcPort, tcp.Sequence, tcp.Acknowledgment)
								ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
								tcp.CalculateChecksum(ipv4)

								ipv4.Data = tcp.Bytes()
								ipv4.CalculateTotalLength()
								ipv4.CalculateChecksum()

								ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
								if err := dnw.Send(ethernetFrame); err != nil {
									return err
								}
								return nil
							}

							// dnw.PassiveCh <- &p.Passive{
							// 	EthernetFrame: ethernetFrame,
							// 	IPv4:          ipv4,
							// 	TCP:           tcp,
							// }
							continue

						default:
							// dnw.PassiveCh <- &p.Passive{
							// 	EthernetFrame: ethernetFrame,
							// 	IPv4:          ipv4,
							// 	TCP:           tcp,
							// }
						}
					}
				}
			}
		}
	}

	return nil
}

func (dnw *debugNetworkInterface) SendHTTPget(srcPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	http := p.NewHTTP()
	tcp := p.NewTCPWithData(srcPort, http.Bytes(), prevSequence, prevAcknowledgment)
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dstMACAddr := p.HardwareAddr(firsthopMACAddr)
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) Recieve() error {
	log.Println("in Recive")

	epollfd, err := unix.EpollCreate1(0)
	if err != nil {
		return err
	}

	if err := unix.EpollCtl(
		epollfd,
		unix.EPOLL_CTL_ADD,
		dnw.Socket,
		&unix.EpollEvent{
			Events: unix.EPOLLIN,
			Fd:     int32(dnw.Socket),
		},
	); err != nil {
		return err
	}

	events := make([]unix.EpollEvent, 10)
	for {
		log.Println("in loop")

		fds, err := unix.EpollWait(epollfd, events, -1)
		if err != nil {
			return err
		}

		log.Printf("fds length: %d\n", fds)

		for i := 0; i < fds; i++ {
			if events[i].Fd == int32(dnw.Socket) {
				recieved := make([]byte, 1500)
				n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
				if err != nil {
					if n == -1 {
						log.Println("-1 unix.Recvfrom")
						continue
					}
					return err
				}

				log.Println("recieved")

				ethernetFrame := &p.EthernetFrame{
					Header: &p.EthernetHeader{
						Dst: p.HardwareAddr(recieved[0:6]),
						Src: p.HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				HARDWAREADDR_BROADCAST := p.HardwareAddr([6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})

				switch ethernetFrame.Header.Typ {
				case p.ETHER_TYPE_ARP:
					switch ethernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved ARP")

						arp := p.ParsedARP(ethernetFrame.Data)

						// dnw.PassiveCh <- &p.Passive{
						// 	EthernetFrame: ethernetFrame,
						// 	ARP:           arp,
						// }
						_ = arp
					}
				case p.ETHER_TYPE_IPv4:
					switch ethernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved IPv4")

						ipv4 := &p.IPv4{
							Version:        ethernetFrame.Data[0] >> 4,
							Ihl:            ethernetFrame.Data[0] << 4 >> 4,
							Tos:            ethernetFrame.Data[1],
							TotalLength:    binary.BigEndian.Uint16(ethernetFrame.Data[2:4]),
							Identification: binary.BigEndian.Uint16(ethernetFrame.Data[4:6]),
							Flags:          ethernetFrame.Data[6],
							FragmentOffset: binary.BigEndian.Uint16(ethernetFrame.Data[6:8]),
							Ttl:            ethernetFrame.Data[8],
							Protocol:       ethernetFrame.Data[9],
							HeaderChecksum: binary.BigEndian.Uint16(ethernetFrame.Data[10:12]),
							SrcAddr:        binary.BigEndian.Uint32(ethernetFrame.Data[12:16]),
							DstAddr:        binary.BigEndian.Uint32(ethernetFrame.Data[16:20]),
						}

						// switch ipv4.DstAddr {
						// case dnw.IPAdder:
						// 	dnw.PassiveCh <- &p.Passive{
						// 		EthernetFrame: ethernetFrame,
						// 		IPv4:          ipv4,
						// 	}
						// }
						_ = ipv4
					}
				}

				log.Println("end inner loop")
			}
		}
	}

	return nil
}
