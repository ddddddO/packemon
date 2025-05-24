//go:build linux
// +build linux

package debugging

import (
	"fmt"
	"log"
	"os"
	"time"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

func (dnw *debugNetworkInterface) FlowBGP() error {
	var srcPort uint16 = 0x2797 // TODO: 毎回変えること
	var dstPort uint16 = BGP_PORT
	var srcIPAddr uint32 = 0xac110004                                         // 172.17.0.4
	var dstIPAddr uint32 = 0xac110005                                         // 172.17.0.5
	srcMACAddr := p.HardwareAddr(dnw.Intf.HardwareAddr)                       // BGPRouter1
	dstMACAddr := p.HardwareAddr([6]byte{0xd2, 0xd2, 0x41, 0x7c, 0x25, 0xcb}) // BGPRouter2

	// SYN
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

	prevSentBGPOpen := false
	prevPassiveKeepalive := false

	var tmpSeqForKeepalive uint32
	var tmpAckForKeepalive uint32

	triggerBGPNotification := 3 // 一旦 keepalive を3回受信後にこちらから Notification 投げる
	for {
		recieved := make([]byte, 1500)
		n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
		if err != nil {
			if n == -1 {
				continue
			}
			return err
		}

		// TODO: nまで渡すようにしてうまくいくように修正
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

						// ここで BGP open を送る
						if err := dnw.BGPOpen(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
							return err
						}
						prevSentBGPOpen = true
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_ACK {
						log.Println("passive TCP_FLAGS_ACK")
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
						log.Println("passive TCP_FLAGS_PSH_ACK")

						// ここで対向から BGP の OPEN / KEEPALIVE / UPDATE / NOTIFICATION が取れる
						if IsBGPOpen(tcp.Data) {
							fmt.Println("Open")
							bgpopen := ParsedBGPOpen(tcp.Data)
							fmt.Printf("%x\n", bgpopen.Typ)

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 102 /* TODO: ほんとは、bgpopen.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							tmpSeqForKeepalive = tcp.Sequence
							tmpAckForKeepalive = tcp.Acknowledgment

							continue
						}

						if IsBGPKeepalive(tcp.Data) {
							fmt.Println("Keepalive")

							triggerBGPNotification--
							prevPassiveKeepalive = true

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 19 /* TODO: ほんとは、.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							if triggerBGPNotification == 0 {
								fmt.Println("Sent BGP Notification")
								if err := dnw.BGPNotification(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
									return err
								}
								continue
							}

							if prevSentBGPOpen {
								// ここで、Keepalive 送るみたい。キャプチャ見ると
								// TODO: ここで送った後は、ticker か何か使って一定周期で keepalive 送るようにする?現状、対向の keepalive 受信後にこちらも送信としてる
								if err := dnw.BGPKeepalive(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tmpSeqForKeepalive, tmpAckForKeepalive); err != nil {
									return err
								}
								prevSentBGPOpen = false
								fmt.Println("Sent BGP Keepalive")

								if prevPassiveKeepalive {
								BREAK:
									// 送った keepalive の ack を受信する
									for {
										fmt.Println("Waiting passive Ack of keepalive...")

										recieved := make([]byte, 1500)
										n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
										if err != nil {
											if n == -1 {
												continue
											}
											return err
										}

										// TODO: nまで渡すようにしてうまくいくか修正する
										ethernetFrame := p.ParsedEthernetFrame(recieved)
										switch ethernetFrame.Header.Typ {
										case p.ETHER_TYPE_IPv4:
											ipv4 := p.ParsedIPv4(ethernetFrame.Data)

											switch ipv4.Protocol {
											case p.IPv4_PROTO_TCP:
												tcp := p.ParsedTCP(ipv4.Data)

												switch tcp.DstPort {
												case srcPort: // synパケットの送信元ポート
													if tcp.Flags == p.TCP_FLAGS_ACK {
														time.Sleep(1000 * time.Millisecond)
														if err := dnw.BGPUpdate(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Acknowledgment, tcp.Sequence); err != nil {
															fmt.Fprintln(os.Stderr, err)
														}
														fmt.Println("Sent BGP Update")
														prevPassiveKeepalive = false

														break BREAK
													}
												}
											}
										}
									}
								}
							} else {
								if err := dnw.BGPKeepalive(srcPort, dstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
									return err
								}
								fmt.Println("Sent BGP Keepalive")
							}
						}

						if IsBGPUpdate(tcp.Data) {
							fmt.Println("Update")

							// Ack
							tcp := p.NewTCPAckForPassiveData(srcPort, dstPort, tcp.Sequence, tcp.Acknowledgment, 23 /* TODO: ほんとは、.Length を int にしたものを */)
							ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)
							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()
							ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}
							continue
						}

						if IsBGPNotification(tcp.Data) {
							fmt.Println("Notification")
							continue
						}

						continue
					}

					if tcp.Flags == p.TCP_FLAGS_FIN_ACK {
						log.Println("passive TCP_FLAGS_FIN_ACK")

						// Ack
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
				}
			}
		}
	}

	return nil
}
