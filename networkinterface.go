package packemon

import (
	"bytes"
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

				switch recievedEthernetFrame.Header.Typ {
				case ETHER_TYPE_ARP:
					arp := &ARP{
						HardwareType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[0:2]),
						ProtocolType:       binary.BigEndian.Uint16(recievedEthernetFrame.Data[2:4]),
						HardwareAddrLength: recievedEthernetFrame.Data[4],
						ProtocolLength:     recievedEthernetFrame.Data[5],
						Operation:          binary.BigEndian.Uint16(recievedEthernetFrame.Data[6:8]),

						SenderHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[8:14]),
						SenderIPAddr:       binary.BigEndian.Uint32(recievedEthernetFrame.Data[14:18]),

						TargetHardwareAddr: HardwareAddr(recievedEthernetFrame.Data[18:24]),
						TargetIPAddr:       binary.BigEndian.Uint32(recievedEthernetFrame.Data[24:28]),
					}

					nw.PassiveCh <- &Passive{
						EthernetFrame: recievedEthernetFrame,
						ARP:           arp,
					}
					continue

				case ETHER_TYPE_IPv4:
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

						Data: recievedEthernetFrame.Data[20:],
					}

					switch ipv4.Protocol {
					case IPv4_PROTO_ICMP:
						icmp := &ICMP{
							Typ:        ipv4.Data[0],
							Code:       ipv4.Data[1],
							Checksum:   binary.BigEndian.Uint16(ipv4.Data[2:4]),
							Identifier: binary.BigEndian.Uint16(ipv4.Data[4:6]),
							Sequence:   binary.BigEndian.Uint16(ipv4.Data[6:8]),
							Data:       ipv4.Data[8:],
						}
						nw.PassiveCh <- &Passive{
							EthernetFrame: recievedEthernetFrame,
							IPv4:          ipv4,
							ICMP:          icmp,
						}

						continue
					case IPv4_PROTO_TCP:
						tcp := &TCP{
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
						case PORT_HTTP:
							if tcp.Flags == TCP_FLAGS_PSH_ACK {
								lineLength := bytes.Index(tcp.Data, []byte{0x0d, 0x0a}) // "\r\n"
								if lineLength == -1 {
									// TODO: こういうフォーマット不正みたいなパケットは、Dataをviewできた方がいいかも
									nw.PassiveCh <- &Passive{
										EthernetFrame: recievedEthernetFrame,
										IPv4:          ipv4,
										TCP:           tcp,
									}
									continue
								}

								line := tcp.Data[0 : lineLength+1]
								split := bytes.Split(line, []byte{0x20}) // 半角スペース
								if len(split) >= 3 {
									http := &HTTP{
										Method:  string(split[0]),
										Uri:     string(split[1]),
										Version: string(split[2]),
									}

									hostLineLength := bytes.Index(tcp.Data[lineLength+2:], []byte{0x0d, 0x0a})
									if hostLineLength == -1 {
										nw.PassiveCh <- &Passive{
											EthernetFrame: recievedEthernetFrame,
											IPv4:          ipv4,
											TCP:           tcp,
											HTTP:          http,
										}
										continue
									}

									host := bytes.TrimPrefix(tcp.Data[lineLength+2:lineLength+2+hostLineLength], []byte{0x48, 0x6f, 0x73, 0x74, 0x3a}) // "Host:"
									http.Host = strings.TrimSpace(string(host))

									nw.PassiveCh <- &Passive{
										EthernetFrame: recievedEthernetFrame,
										IPv4:          ipv4,
										TCP:           tcp,
										HTTP:          http,
									}
									continue
								}
							}

							nw.PassiveCh <- &Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
								TCP:           tcp,
							}
							continue

						default:
							nw.PassiveCh <- &Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
								TCP:           tcp,
							}
						}

						continue
					case IPv4_PROTO_UDP:
						udp := &UDP{
							SrcPort:  binary.BigEndian.Uint16(ipv4.Data[0:2]),
							DstPort:  binary.BigEndian.Uint16(ipv4.Data[2:4]),
							Length:   binary.BigEndian.Uint16(ipv4.Data[4:6]),
							Checksum: binary.BigEndian.Uint16(ipv4.Data[6:8]),
							Data:     ipv4.Data[8:],
						}

						// DNS以外は一旦udpまでのみviewする
						if udp.DstPort != PORT_DNS && udp.SrcPort != PORT_DNS {
							nw.PassiveCh <- &Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
								UDP:           udp,
							}
							continue
						}

						// TODO: 53確かtcpもあったからそれのハンドリング考慮するいつか
						// TODO: nslookup github.com でipv6用のDNSクエリ・レスポンスも返ってきてるのでそれも対応
						//       query.type == AAAA で判別可能
						flags := binary.BigEndian.Uint16(udp.Data[2:4])
						if udp.DstPort == PORT_DNS && flags == DNS_REQUEST {
							qCnt := binary.BigEndian.Uint16(udp.Data[4:6])
							anCnt := binary.BigEndian.Uint16(udp.Data[6:8])
							auCnt := binary.BigEndian.Uint16(udp.Data[8:10])
							adCnt := binary.BigEndian.Uint16(udp.Data[10:12])

							// 一旦Questionsは1固定で進める
							// また、domainは、0x00 までとなる。そういう判定処理
							offset := bytes.IndexByte(udp.Data[12:], 0x00) + 12 + 1
							q := &Queries{
								Domain: udp.Data[12:offset],
								Typ:    binary.BigEndian.Uint16(udp.Data[offset : offset+2]),
								Class:  binary.BigEndian.Uint16(udp.Data[offset+2 : offset+4]),
							}

							dns := &DNS{
								TransactionID: binary.BigEndian.Uint16(udp.Data[0:2]),
								Flags:         flags,
								Questions:     qCnt,
								AnswerRRs:     anCnt,
								AuthorityRRs:  auCnt,
								AdditionalRRs: adCnt,
								Queries:       q,
							}

							nw.PassiveCh <- &Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
								UDP:           udp,
								DNS:           dns,
							}

							continue
						}

						if udp.SrcPort == PORT_DNS && flags == DNS_RESPONSE {
							qCnt := binary.BigEndian.Uint16(udp.Data[4:6])
							anCnt := binary.BigEndian.Uint16(udp.Data[6:8])
							auCnt := binary.BigEndian.Uint16(udp.Data[8:10])
							adCnt := binary.BigEndian.Uint16(udp.Data[10:12])

							// 一旦Questionsは1固定として進める
							// また、domainは、0x00 までとなる。そういう判定処理
							offset := bytes.IndexByte(udp.Data[12:], 0x00) + 12 + 1
							q := &Queries{
								Domain: udp.Data[12:offset],
								Typ:    binary.BigEndian.Uint16(udp.Data[offset : offset+2]),
								Class:  binary.BigEndian.Uint16(udp.Data[offset+2 : offset+4]),
							}
							// 一旦Answersは1固定として進める
							offsetOfAns := offset + 4
							a := &Answer{
								Name:       binary.BigEndian.Uint16(udp.Data[offsetOfAns : offsetOfAns+2]),
								Typ:        binary.BigEndian.Uint16(udp.Data[offsetOfAns+2 : offsetOfAns+4]),
								Class:      binary.BigEndian.Uint16(udp.Data[offsetOfAns+4 : offsetOfAns+6]),
								Ttl:        binary.BigEndian.Uint32(udp.Data[offsetOfAns+6 : offsetOfAns+10]),
								DataLength: binary.BigEndian.Uint16(udp.Data[offsetOfAns+10 : offsetOfAns+12]),
								Address:    binary.BigEndian.Uint32(udp.Data[offsetOfAns+12 : offsetOfAns+16]),
							}

							dns := &DNS{
								TransactionID: binary.BigEndian.Uint16(udp.Data[0:2]),
								Flags:         flags,
								Questions:     qCnt,
								AnswerRRs:     anCnt,
								AuthorityRRs:  auCnt,
								AdditionalRRs: adCnt,
								Queries:       q,
								Answers:       []*Answer{a},
							}

							nw.PassiveCh <- &Passive{
								EthernetFrame: recievedEthernetFrame,
								IPv4:          ipv4,
								UDP:           udp,
								DNS:           dns,
							}

							continue
						}
					default:
						nw.PassiveCh <- &Passive{
							EthernetFrame: recievedEthernetFrame,
							IPv4:          ipv4,
						}
					}
				}
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
