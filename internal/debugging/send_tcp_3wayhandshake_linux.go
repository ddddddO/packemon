//go:build linux
// +build linux

package debugging

import (
	"bytes"
	"log"

	"github.com/ddddddO/packemon"
	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

func (dnw *debugNetworkInterface) SendTCP3wayhandshake(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0xa018
	var dstPort uint16 = 0x0050       // 80
	var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78
	var dstIPAddr uint32 = 0xc0a80a6e // raspberry pi
	dstMACAddr := p.HardwareAddr(firsthopMACAddr)
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)

	tcp := p.NewTCPSyn(srcPort, dstPort)
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
								tcp := p.NewTCPAck(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment)
								ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
								tcp.CalculateChecksum(ipv4)

								ipv4.Data = tcp.Bytes()
								ipv4.CalculateTotalLength()
								ipv4.CalculateChecksum()

								ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
								if err := dnw.Send(ethernetFrame); err != nil {
									return err
								}

								if err := dnw.SendHTTPget(srcPort, dstPort, srcIPAddr, dstIPAddr, firsthopMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
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

									tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, resp.Len())
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
									tcp = p.NewTCPFinAck(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment)
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
								tcp := p.NewTCPAck(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment)
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
