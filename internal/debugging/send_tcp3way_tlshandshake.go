package debugging

import (
	"bytes"
	"log"

	p "github.com/ddddddO/packemon"
	"golang.org/x/sys/unix"
)

/*
TODO: 旧PCだとうまくいって、新PCだとうまくいかない、時があった。一時的なもの？ダメだった後に再起動した後は大丈夫だった。以下はダメだった時の状況
新PCでWiresharkで見ると、ServerHelloは受信してるが、このコードのServerHello受信ブロックに入ってきておらず、debug printするとtcp.Dataのパケットがずれているみたい。
この状況は、main.goのebpfの箇所を丸っとコメントアウトしてこの関数実行 -> コメントインして実行するとなるよう
TCP 3way handshake途中にカーネルが自動でRSTパケット送るとそれ以後サーバからのパケットが異なる？
サーバのtls-serverを再起動してこの関数を実行すると成功する。tls-server停止直後、こちらにfin/ackを送ってる（clientがそれまでこの関数を実行していた時の送信元ポート宛てに）
*/
func (dnw *debugNetworkInterface) SendTCP3wayAndTLShandshake(firsthopMACAddr [6]byte) error {
	var srcPort uint16 = 0xa31a
	var dstPort uint16 = 0x28cb // 10443
	// var srcIPAddr uint32 = 0xac184fcf // 172.23.242.78 / 旧PC
	var srcIPAddr uint32 = 0xac163718 // 172.22.55.24 / 新PC
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

					if tcp.Flags == p.TCP_FLAGS_ACK {
						log.Println("passive TCP_FLAGS_ACK")
						continue
					}

					if tcp.Flags == p.TCP_FLAGS_PSH_ACK {
						log.Println("passive TCP_FLAGS_PSH_ACK")

						tlsHandshakeType := []byte{tcp.Data[5]}
						tlsContentType := []byte{tcp.Data[0]}

						log.Printf("\ttlsHandshakeType: %x\n", tlsHandshakeType)
						log.Printf("\ttlsContentType: %x\n", tlsContentType)
						log.Printf("\tTCP data: %x\n", tcp.Data[:100])

						// ServerHello/Certificate/ServerHelloDone を受信
						// TODO: (10)443ポートがdstで絞った方がいいかも
						if bytes.Equal(tlsHandshakeType, []byte{0x02}) && bytes.Equal(tlsContentType, []byte{p.TLS_CONTENT_TYPE_HANDSHAKE}) {
							log.Println("passive TLS ServerHello/Certificate/ServerHelloDone")

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
							tlsApplicationData := p.NewTLSApplicationData([]byte("Hellooooooo!!\n"), keyblock, clientSequence)
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

						log.Println("end push/ack")
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

	return nil
}
