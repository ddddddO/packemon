package debugging

import (
	"bytes"
	"log"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

// SendTCP3wayAndTLShandshake とほぼ同じ。違いは client から送る Application Data が http のフォーマット
func (dnw *debugNetworkInterface) SendHTTPSGetAfterTCP3wayAndTLShandshake(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0xa331

	var dstPort uint16 = 0x28cb // 10443
	// var dstPort uint16 = 0x01bb // 443

	var srcIPAddr uint32 = 0xac163718
	var dstIPAddr uint32 = 0xc0a80a70 // raspberry pi . raspberry pi 上で https-server 起動で、うまくいった

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

	tlsClientHello := p.NewTLSClientHello()
	var tlsServerHello *p.TLSServerHello
	var tlsClientKeyExchange *p.TLSClientKeyExchange
	var tlsClientFinished []byte

	var keyblock *p.KeyBlock
	var clientSequence int
	var master []byte

	for {
		log.Println("in loop")

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

						// ここで TLS Client Helloを送る
						if err := dnw.SendTLSClientHello(tlsClientHello, srcPort, dstPort, srcIPAddr, dstIPAddr, firsthopMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
							return err
						}

						continue
					}

					// ここでのServer Hello(ack)受信後の処理はうまくいった
					// 関連: https://github.com/ddddddO/packemon/issues/64
					// Wireshark 見るに、このackのパケットを後続のpsh/ackのパケット2つのtcp data部分をつなげて、ServerHello/Certificate/ServerHelloDone みたい
					// 上記リンクの、1パケットパターンのパケットと2パケットパターンのパケット見比べて確認した
					if tcp.Flags == p.TCP_FLAGS_ACK {
						log.Println("passive TCP_FLAGS_ACK")

						tlsHandshakeType := []byte{tcp.Data[5]}
						tlsContentType := []byte{tcp.Data[0]}

						// ServerHello/Certificate/ServerHelloDone がセグメント分割されたパケットで届くことが多々あるため、このブロック内で連続して受信している
						// TODO: (10)443ポートがdstで絞った方がいいかも
						if bytes.Equal(tlsHandshakeType, []byte{0x02}) && bytes.Equal(tlsContentType, []byte{p.TLS_CONTENT_TYPE_HANDSHAKE}) {
							log.Println("[ACK] passive TLS ServerHello(with Certificate/ServerHelloDone ?)")
							log.Printf("\tTCP data: %x\n", tcp.Data)

							for {
								recieved := make([]byte, 1500)
								n, _, err := unix.Recvfrom(dnw.Socket, recieved, 0)
								if err != nil {
									if n == -1 {
										continue
									}
									return err
								}
								eth := p.ParsedEthernetFrame(recieved)
								ip := p.ParsedIPv4(eth.Data)
								t := p.ParsedTCP(ip.Data)

								if t.Flags == p.TCP_FLAGS_PSH_ACK {
									log.Println("[PSH_ACK] passive TLS ServerHello(with Certificate/ServerHelloDone !!!???)")

									// tcp data の末尾の0パディングを取り除く
									tmp1 := tcp.Data
									for offset := len(tcp.Data) - 2; bytes.Equal(tcp.Data[offset:offset+2], []byte{00, 00}); offset -= 2 {
										tmp1 = tmp1[:len(tmp1)-2]
									}
									tmp2 := t.Data
									for offset := len(t.Data) - 4; bytes.Equal(t.Data[offset:offset+4], []byte{00, 00, 00, 00}); offset -= 4 {
										tmp2 = tmp2[:len(tmp2)-4]
									}
									mergedTCPData := append(tmp1, tmp2...)

									tlsServerHello = p.ParsedTLSServerHello(mergedTCPData)
									if err := tlsServerHello.Certificate.Validate(); err != nil {
										return err
									}

									// ackを返し
									tcp := p.NewTCPAck(srcPort, dstPort, t.Sequence, t.Acknowledgment)
									ipv4 := p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
									tcp.CalculateChecksum(ipv4)

									ipv4.Data = tcp.Bytes()
									ipv4.CalculateTotalLength()
									ipv4.CalculateChecksum()

									ethernetFrame := p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
									if err := dnw.Send(ethernetFrame); err != nil {
										return err
									}

									// さらに ClientKeyExchange や Finished などを返す
									tlsClientKeyExchange, keyblock, clientSequence, master, tlsClientFinished = p.NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
										tlsClientHello,
										tlsServerHello,
									)
									tcp = p.NewTCPWithData(srcPort, dstPort, tlsClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
									ipv4 = p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
									tcp.CalculateChecksum(ipv4)

									ipv4.Data = tcp.Bytes()
									ipv4.CalculateTotalLength()
									ipv4.CalculateChecksum()

									ethernetFrame = p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
									if err := dnw.Send(ethernetFrame); err != nil {
										return err
									}

									break
								}
							}

							continue
						}

						continue
					}

					if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
						log.Println("passive TCP_FLAGS_PSH_ACK")

						tlsHandshakeType := []byte{tcp.Data[5]}
						tlsContentType := []byte{tcp.Data[0]}

						log.Printf("\ttcp data: %x\n\n", tcp.Data[0:10])

						log.Printf("\ttlsHandshakeType: %x\n", tlsHandshakeType)
						log.Printf("\ttlsContentType: %x\n", tlsContentType)

						// ServerHelloを受信
						// TODO: (10)443ポートがdstで絞った方がいいかも
						// SeverHello(0x02)
						if bytes.Equal(tlsHandshakeType, []byte{0x02}) && bytes.Equal(tlsContentType, []byte{p.TLS_CONTENT_TYPE_HANDSHAKE}) {
							log.Printf("tlsHandshakeType: %x\n", tlsHandshakeType)

							log.Println("passive TLS ServerHello")
							// TODO: server から、ServerHello/Certificate/ServerHelloDone でひとまとまりで返ってくればパースできるが、ServerHello と Certificate/ServerHelloDone がわかれて返ってくることがある。それで失敗してるよう？
							// 分かれてるとき、ServerHell はフラグが ACK だけど、分かれてないとき PSH/ACK
							tlsServerHello = p.ParsedTLSServerHello(tcp.Data)
							if err := tlsServerHello.Certificate.Validate(); err != nil {
								return err
							}

							// ackを返し
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

							// さらに ClientKeyExchange や Finished などを返す
							tlsClientKeyExchange, keyblock, clientSequence, master, tlsClientFinished = p.NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
								tlsClientHello,
								tlsServerHello,
							)
							tcp = p.NewTCPWithData(srcPort, dstPort, tlsClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
							ipv4 = p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)

							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()

							ethernetFrame = p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							continue
						}

						// ChangeCipherSpec/Finishedを受信
						// TODO: (10)443ポートがdstとかもっと絞った方がいいかも
						if bytes.Equal(tlsContentType, []byte{p.TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC}) {
							log.Println("recieved ChangeCipherSpec/Finished !!")

							verifingData := &p.ForVerifing{
								Master:            master,
								ClientHello:       tlsClientHello,
								ServerHello:       tlsServerHello,
								ClientKeyExchange: tlsClientKeyExchange.ClientKeyExchange,
								ClientFinished:    tlsClientFinished,
							}
							tlsChangeCiperSpecAndFinished := p.ParsedTLSChangeCipherSpecAndFinished(tcp.Data, keyblock, clientSequence, verifingData)
							log.Printf("\tChangeCipherSpecProtocol.RecordLayer.ContentType: %x\n", tlsChangeCiperSpecAndFinished.ChangeCipherSpecProtocol.RecordLayer.ContentType)
							log.Printf("\tFinished.RawEncrypted:\n%x\n", tlsChangeCiperSpecAndFinished.Finished.RawEncrypted)

							// TODO: 上のParsed内でserverからきたFinishedの検証してるけど、この辺りに持ってきた方がいいかも

							// Finishedの検証が成功したので、以降からApplicationDataをやりとり
							log.Println("Send TLS Application DATA")

							clientSequence++
							httpGetReq := p.NewHTTP()
							tlsApplicationData := p.NewTLSApplicationData(httpGetReq.Bytes(), keyblock, clientSequence)

							tcp = p.NewTCPWithData(srcPort, dstPort, tlsApplicationData, tcp.Acknowledgment, tcp.Sequence)
							ipv4 = p.NewIPv4(p.IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
							tcp.CalculateChecksum(ipv4)

							ipv4.Data = tcp.Bytes()
							ipv4.CalculateTotalLength()
							ipv4.CalculateChecksum()

							ethernetFrame = p.NewEthernetFrame(dstMACAddr, srcMACAddr, p.ETHER_TYPE_IPv4, ipv4.Bytes())
							if err := dnw.Send(ethernetFrame); err != nil {
								return err
							}

							continue
						}
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

	return nil
}
