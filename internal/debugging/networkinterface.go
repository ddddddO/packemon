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
	ipv4 := p.NewIPv4(p.IPv4_PROTO_ICMP, 0xa32b661d) // dst: 163.43.102.29 = tools.m-bsys.com
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
	ipv4 := p.NewIPv4(p.IPv4_PROTO_UDP, 0x08080808) // 8.8.8.8 = DNSクエリ用
	ipv4.Data = udp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendTCPsyn(firsthopMACAddr [6]byte) error {
	tcp := p.NewTCPSyn()
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			buf := &bytes.Buffer{}
			packemon.WriteUint32(buf, ipv4.SrcAddr)
			packemon.WriteUint32(buf, ipv4.DstAddr)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			packemon.WriteUint16(buf, uint16(len(tcp.Bytes())))
			return buf.Bytes()
		}()

		forTCPChecksum := &bytes.Buffer{}
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
	return dnw.Send(ethernetFrame)
}

func (dnw *debugNetworkInterface) SendTCP3wayhandshake(firsthopMACAddr [6]byte) error {
	tcp := p.NewTCPSyn()
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			buf := &bytes.Buffer{}
			packemon.WriteUint32(buf, ipv4.SrcAddr)
			packemon.WriteUint32(buf, ipv4.DstAddr)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			packemon.WriteUint16(buf, uint16(len(tcp.Bytes())))
			return buf.Bytes()
		}()

		forTCPChecksum := &bytes.Buffer{}
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
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

				recievedEthernetFrame := &p.EthernetFrame{
					Header: &p.EthernetHeader{
						Dst: p.HardwareAddr(recieved[0:6]),
						Src: p.HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				switch recievedEthernetFrame.Header.Typ {
				case p.ETHER_TYPE_IPv4:
					ipv4 := &p.IPv4{
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

						Data: recievedEthernetFrame.Data[20:],
					}

					switch ipv4.Protocol {
					case p.IPv4_PROTO_TCP:
						tcp := &p.TCP{
							SrcPort:        binary.BigEndian.Uint16(ipv4.Data[0:2]),
							DstPort:        binary.BigEndian.Uint16(ipv4.Data[2:4]),
							Sequence:       binary.BigEndian.Uint32(ipv4.Data[4:8]),
							Acknowledgment: binary.BigEndian.Uint32(ipv4.Data[8:12]),
							HeaderLength:   binary.BigEndian.Uint16(ipv4.Data[12:14]) >> 8,
							Flags:          binary.BigEndian.Uint16(ipv4.Data[12:14]) << 4,
							Window:         binary.BigEndian.Uint16(ipv4.Data[14:16]),
							Checksum:       binary.BigEndian.Uint16(ipv4.Data[16:18]),
							UrgentPointer:  binary.BigEndian.Uint16(ipv4.Data[18:20]),
						}

						// Wiresharkとpackemonのパケット詳細見比べるに、
						// ( tcpヘッダーのheader lengthを10進数に変換した値 / 4 ) - 20 = options のbyte数 になるよう
						optionLength := tcp.HeaderLength>>2 - 20
						if optionLength > 0 {
							tcp.Options = ipv4.Data[20 : optionLength+20]
						}
						tcp.Data = ipv4.Data[optionLength+20:]

						switch tcp.DstPort {
						case 0x9e13: // synパケットの送信元ポート
							if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
								lineLength := bytes.Index(tcp.Data, []byte{0x0d, 0x0a}) // "\r\n"
								if lineLength == -1 {
									log.Println("-1")
									continue
								}
								log.Println("passive TCP_FLAGS_PSH_ACK")
							}

							if tcp.Flags == p.TCP_FLAGS_SYN_ACK {
								log.Println("passive TCP_FLAGS_SYN_ACK")
								log.Printf("%+v\n", tcp)

								// syn/ackを受け取ったのでack送信
								tcp := p.NewTCPAck(tcp.Sequence, tcp.Acknowledgment)
								ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0xa32b661d) // 163.43.102.29 = tools.m-bsys.com こちらで、ack返ってきた
								// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
								// 「「チェックサム」フィールド：16bit幅」
								tcp.Checksum = func() uint16 {
									pseudoTCPHeader := func() []byte {
										buf := &bytes.Buffer{}
										packemon.WriteUint32(buf, ipv4.SrcAddr)
										packemon.WriteUint32(buf, ipv4.DstAddr)
										padding := byte(0x00)
										buf.WriteByte(padding)
										buf.WriteByte(ipv4.Protocol)
										packemon.WriteUint16(buf, uint16(len(tcp.Bytes())))
										return buf.Bytes()
									}()

									forTCPChecksum := &bytes.Buffer{}
									forTCPChecksum.Write(pseudoTCPHeader)
									forTCPChecksum.Write(tcp.Bytes())
									return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
								}()
								ipv4.Data = tcp.Bytes()
								ipv4.CalculateTotalLength()
								ipv4.CalculateChecksum()
								dst := p.HardwareAddr(firsthopMACAddr)
								src := p.HardwareAddr(dnw.Intf.HardwareAddr)
								ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
								if err := dnw.Send(ethernetFrame); err != nil {
									return err
								}
							}

							// dnw.PassiveCh <- &p.Passive{
							// 	EthernetFrame: recievedEthernetFrame,
							// 	IPv4:          ipv4,
							// 	TCP:           tcp,
							// }
							continue

						default:
							// dnw.PassiveCh <- &p.Passive{
							// 	EthernetFrame: recievedEthernetFrame,
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

func (dnw *debugNetworkInterface) SendHTTPget(firsthopMACAddr [6]byte) error {
	http := p.NewHTTP()
	tcp := p.NewTCPWithData(http.Bytes())
	ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, 0x88bb0609) // 136.187.6.9 = research.nii.ac.jp
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// 「「チェックサム」フィールド：16bit幅」
	tcp.Checksum = func() uint16 {
		pseudoTCPHeader := func() []byte {
			buf := &bytes.Buffer{}
			packemon.WriteUint32(buf, ipv4.SrcAddr)
			packemon.WriteUint32(buf, ipv4.DstAddr)
			padding := byte(0x00)
			buf.WriteByte(padding)
			buf.WriteByte(ipv4.Protocol)
			packemon.WriteUint16(buf, uint16(len(tcp.Bytes())))
			return buf.Bytes()
		}()
		forTCPChecksum := &bytes.Buffer{}
		forTCPChecksum.Write(pseudoTCPHeader)
		forTCPChecksum.Write(tcp.Bytes())
		return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
	}()
	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()
	dst := p.HardwareAddr(firsthopMACAddr)
	src := p.HardwareAddr(dnw.Intf.HardwareAddr)
	ethernetFrame := p.NewEthernetFrame(dst, src, p.ETHER_TYPE_IPv4, ipv4.Bytes())
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

				recievedEthernetFrame := &p.EthernetFrame{
					Header: &p.EthernetHeader{
						Dst: p.HardwareAddr(recieved[0:6]),
						Src: p.HardwareAddr(recieved[6:12]),
						Typ: binary.BigEndian.Uint16(recieved[12:14]), // タグVLANだとズレる
					},
					Data: recieved[14:],
				}

				HARDWAREADDR_BROADCAST := [6]uint8{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

				switch recievedEthernetFrame.Header.Typ {
				case p.ETHER_TYPE_ARP:
					switch recievedEthernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved ARP")

						arp := &p.ARP{
							HardwareType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[0:2]),
							ProtocolType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
							HardwareAddrLength: recievedEthernetFrame.Data[4],
							ProtocolLength:     recievedEthernetFrame.Data[5],
							Operation:          binary.BigEndian.Uint16(recievedEthernetFrame.Data[6:8]),

							SenderHardwareAddr: p.HardwareAddr(recievedEthernetFrame.Data[8:14]),
							SenderIPAddr:       binary.BigEndian.Uint32(recievedEthernetFrame.Data[14:18]),

							TargetHardwareAddr: p.HardwareAddr(recievedEthernetFrame.Data[18:24]),
							TargetIPAddr:       binary.BigEndian.Uint32(recievedEthernetFrame.Data[24:28]),
						}

						// dnw.PassiveCh <- &p.Passive{
						// 	EthernetFrame: recievedEthernetFrame,
						// 	ARP:           arp,
						// }
						_ = arp
					}
				case p.ETHER_TYPE_IPv4:
					switch recievedEthernetFrame.Header.Dst {
					case p.HardwareAddr(dnw.Intf.HardwareAddr), HARDWAREADDR_BROADCAST:
						log.Println("recieved IPv4")

						ipv4 := &p.IPv4{
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

						// switch ipv4.DstAddr {
						// case dnw.IPAdder:
						// 	dnw.PassiveCh <- &p.Passive{
						// 		EthernetFrame: recievedEthernetFrame,
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
