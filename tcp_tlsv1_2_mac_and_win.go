//go:build darwin || windows
// +build darwin windows

// TODO: linux の方のコードとなるべく共通化

package packemon

import (
	"bytes"
	"context"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

func EstablishTCPTLSv1_2AndSendPayload(ctx context.Context, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
	return establishTCPTLSv1_2AndSendPayload(ctx, fIpv4, fTcp, upperLayerData)
}

func EstablishTCPTLSv1_2AndSendPayloadForIPv6(ctx context.Context, fIpv6 *IPv6, fTcp *TCP, upperLayerData []byte) error {
	return establishTCPTLSv1_2AndSendPayloadForIPv6(ctx, fIpv6, fTcp, upperLayerData)
}

// TCP 3way handshake と TLSv1.2 の handshake 後にリクエストする関数
func EstablishTCPTLSv1_2AndSendPayload_CustomImpl(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
	nw, err := NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	srcIPAddr := fIpv4.SrcAddr
	dstIPAddr := fIpv4.DstAddr
	srcMACAddr := fEthrh.Src
	dstMACAddr := fEthrh.Dst

	tcpConn := NewTCPConnection(fTcp.SrcPort, fTcp.DstPort)
	tcp := NewTCPSyn(tcpConn.SrcPort, tcpConn.DstPort)
	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
	if err := nw.Send(ethernetFrame); err != nil {
		return err
	}
	tcpConn.SetState(TCP_STATE_3WAY_HANDSHAKE_SEND_SYN)

	tlsConn := NewTLSv12Connection()

	packetSource := gopacket.NewPacketSource(nw.Handle, layers.LayerTypeEthernet)
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout!")

		case packet := <-packets:
			if packet == nil {
				continue
			}

			received := packet.Data()
			if len(received) < 14 { // Minimum Ethernet frame size
				continue
			}

			ethernetFrame := ParsedEthernetFrame(received)
			if ethernetFrame.Header.Typ != ETHER_TYPE_IPv4 {
				continue
			}

			ipv4 := ParsedIPv4(ethernetFrame.Data)
			if ipv4.Protocol != IPv4_PROTO_TCP {
				continue
			}

			tcp := ParsedTCP(ipv4.Data)
			// TODO: このあたりで(10)443ポートがdstで絞った方がいいかも

			if tcpConn.IsPassiveSynAckForHandshake(tcp) {
				// syn/ackを受け取ったのでack送信
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tcpConn.EstablishedConnection()

				// ここで TLS Client Helloを送る
				if err := SendTLSClientHello(nw, tlsConn.TLSClientHello, tcpConn.SrcPort, tcpConn.DstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
					return err
				}

				continue
			}

			// ServerHello/Certificate/ServerHelloDone がセグメント分割されたパケットで届くことが多々あるため、このブロック内で連続して受信している
			if tcpConn.IsPassiveAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
				for {
					packet := <-packets
					if packet == nil {
						continue
					}

					received := packet.Data()
					if len(received) < 14 { // Minimum Ethernet frame size
						continue
					}

					eth := ParsedEthernetFrame(received)
					ip := ParsedIPv4(eth.Data)
					t := ParsedTCP(ip.Data)

					if tcpConn.IsPassivePshAck(t) {
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

						tlsConn.TLSServerHello = ParsedTLSServerHello(mergedTCPData)
						if err := tlsConn.TLSServerHello.Certificate.Validate(); err != nil {
							return err
						}

						// ackを返し
						tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, t.Sequence, t.Acknowledgment)
						ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						tcp.CalculateChecksum(ipv4)

						ipv4.Data = tcp.Bytes()
						ipv4.CalculateTotalLength()
						ipv4.CalculateChecksum()

						ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
						if err := nw.Send(ethernetFrame); err != nil {
							return err
						}

						// さらに ClientKeyExchange や Finished などを返す
						tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
							tlsConn.TLSClientHello,
							tlsConn.TLSServerHello,
						)
						tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
						ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						tcp.CalculateChecksum(ipv4)

						ipv4.Data = tcp.Bytes()
						ipv4.CalculateTotalLength()
						ipv4.CalculateChecksum()

						ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
						if err := nw.Send(ethernetFrame); err != nil {
							return err
						}

						break
					}
					continue
				}

				continue
			}

			// ServerHelloを受信
			// SeverHello(0x02)
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
				// TODO: server から、ServerHello/Certificate/ServerHelloDone でひとまとまりで返ってくればパースできるが、ServerHello と Certificate/ServerHelloDone がわかれて返ってくることがある。それで失敗してるよう？
				// 分かれてるとき、ServerHello はフラグが ACK だけど、分かれてないとき PSH/ACK
				//  <- そうでもなかった、環境によるみたい。example.com にリクエストすると ServerHello 単体パケットで PSH/ACK
				tlsConn.TLSServerHello = ParsedTLSServerHello(tcp.Data)
				if err := tlsConn.TLSServerHello.Certificate.Validate(); err != nil {
					return err
				}

				// ackを返し
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				// さらに ClientKeyExchange や Finished などを返す
				tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
					tlsConn.TLSClientHello,
					tlsConn.TLSServerHello,
				)
				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
				ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				continue
			}

			// ChangeCipherSpec/Finishedを受信
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveChangeCipherSpecAndFinished(tcp) {
				tlsChangeCiperSpecAndFinished := ParsedTLSChangeCipherSpecAndFinished(tcp.Data, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.VerifingData())
				_ = tlsChangeCiperSpecAndFinished

				// TODO: 上のParsed内でserverからきたFinishedの検証してるけど、この辺りに持ってきた方がいいかも

				tlsConn.EstablishedConnection()

				// Finishedの検証が成功したので、以降からApplicationDataをやりとり
				tlsConn.ClientSequence++
				tlsApplicationData := NewTLSApplicationData(upperLayerData, tlsConn.KeyBlock, tlsConn.ClientSequence)

				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsApplicationData, tcp.Acknowledgment, tcp.Sequence)
				ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				// ここの EtherType は、ユーザー指定のを使う
				// TODO: 他のパケットもそうした方が良い？
				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, fEthrh.Typ, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tlsConn.SetState(TLSv12_STATE_SEND_APPLICATION_DATA)

				continue
			}

			// 送信した Application Data に対するレスポンスを受けて FinAck 送信
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsSendApplicationData() {
				// 受信した Application Data を復号
				lengthOfEncrypted := bytesToInt(tcp.Data[3:5])
				encrypted := tcp.Data[5 : 5+lengthOfEncrypted]
				decrypted := DecryptApplicationData(encrypted, tlsConn.KeyBlock, tlsConn.ClientSequence)
				// log.Printf("👺decrypted application data: %x, %s\n", decrypted, string(decrypted))
				_ = decrypted

				// TLS handshake の終了開始
				tlsConn.ClientSequence++
				tlsEncryptedAlert, _ := EncryptClientMessageForAlert(tlsConn.KeyBlock, tlsConn.ClientSequence, []byte{0x01, 0x00})
				tcp := NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsEncryptedAlert, tcp.Acknowledgment, tcp.Sequence)
				ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				// 続けてFinAck
				tcp = NewTCPFinAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence+uint32(len(tcp.Data)), tcp.Acknowledgment)
				ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				continue
			}

			if tcpConn.IsPassiveFinAck(tcp) {
				// それにack
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksum(ipv4)

				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				ipv4.CalculateChecksum()

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tlsConn.Close()
				tcpConn.Close()
				return nil
			}
		}
	}

	return nil
}

// TCP 3way handshake と TLSv1.2 の handshake 後にリクエストする関数(IPv6用)
func EstablishTCPTLSv1_2AndSendPayloadForIPv6_CustomImpl(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv6 *IPv6, fTcp *TCP, upperLayerData []byte) error {
	nw, err := NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	srcIPAddr := fIpv6.SrcAddr
	dstIPAddr := fIpv6.DstAddr
	srcMACAddr := fEthrh.Src
	dstMACAddr := fEthrh.Dst

	tcpConn := NewTCPConnection(fTcp.SrcPort, fTcp.DstPort)
	tcp := NewTCPSyn(tcpConn.SrcPort, tcpConn.DstPort)
	ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksumForIPv6(ipv6)

	ipv6.Data = tcp.Bytes()
	ipv6.PayloadLength = uint16(len(ipv6.Data))

	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
	if err := nw.Send(ethernetFrame); err != nil {
		return err
	}
	tcpConn.SetState(TCP_STATE_3WAY_HANDSHAKE_SEND_SYN)

	tlsConn := NewTLSv12Connection()

	packetSource := gopacket.NewPacketSource(nw.Handle, layers.LayerTypeEthernet)
	packets := packetSource.Packets()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout!")
		case packet := <-packets:
			if packet == nil {
				continue
			}

			received := packet.Data()
			if len(received) < 14 { // Minimum Ethernet frame size
				continue
			}

			ethernetFrame := ParsedEthernetFrame(received)
			if ethernetFrame.Header.Typ != ETHER_TYPE_IPv4 {
				continue
			}

			ipv6 := ParsedIPv6(ethernetFrame.Data)
			if ipv6.NextHeader != IPv4_PROTO_TCP {
				continue
			}

			tcp := ParsedTCP(ipv6.Data)
			// TODO: このあたりで(10)443ポートがdstで絞った方がいいかも

			if tcpConn.IsPassiveSynAckForHandshake(tcp) {
				// syn/ackを受け取ったのでack送信
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tcpConn.EstablishedConnection()

				// ここで TLS Client Helloを送る
				if err := SendTLSClientHelloForIPv6(nw, tlsConn.TLSClientHello, tcpConn.SrcPort, tcpConn.DstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
					return err
				}

				continue
			}

			// ServerHello/Certificate/ServerHelloDone がセグメント分割されたパケットで届くことが多々あるため、このブロック内で連続して受信している
			if tcpConn.IsPassiveAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
				for {
					packet := <-packets
					if packet == nil {
						continue
					}

					received := packet.Data()
					if len(received) < 14 { // Minimum Ethernet frame size
						continue
					}
					eth := ParsedEthernetFrame(received)
					ip := ParsedIPv6(eth.Data)
					t := ParsedTCP(ip.Data)

					if tcpConn.IsPassivePshAck(t) {
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

						tlsConn.TLSServerHello = ParsedTLSServerHello(mergedTCPData)
						if err := tlsConn.TLSServerHello.Certificate.Validate(); err != nil {
							return err
						}

						// ackを返し
						tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, t.Sequence, t.Acknowledgment)
						ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						tcp.CalculateChecksumForIPv6(ipv6)

						ipv6.Data = tcp.Bytes()
						ipv6.PayloadLength = uint16(len(ipv6.Data))

						ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
						if err := nw.Send(ethernetFrame); err != nil {
							return err
						}

						// さらに ClientKeyExchange や Finished などを返す
						tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
							tlsConn.TLSClientHello,
							tlsConn.TLSServerHello,
						)
						tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
						ipv6 = NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						tcp.CalculateChecksumForIPv6(ipv6)

						ipv6.Data = tcp.Bytes()
						ipv6.PayloadLength = uint16(len(ipv6.Data))

						ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
						if err := nw.Send(ethernetFrame); err != nil {
							return err
						}

						break
					}
					continue
				}

				continue
			}

			// ServerHelloを受信
			// SeverHello(0x02)
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
				// TODO: server から、ServerHello/Certificate/ServerHelloDone でひとまとまりで返ってくればパースできるが、ServerHello と Certificate/ServerHelloDone がわかれて返ってくることがある。それで失敗してるよう？
				// 分かれてるとき、ServerHello はフラグが ACK だけど、分かれてないとき PSH/ACK
				//  <- そうでもなかった、環境によるみたい。example.com にリクエストすると ServerHello 単体パケットで PSH/ACK
				tlsConn.TLSServerHello = ParsedTLSServerHello(tcp.Data)
				if err := tlsConn.TLSServerHello.Certificate.Validate(); err != nil {
					return err
				}

				// ackを返し
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				// さらに ClientKeyExchange や Finished などを返す
				tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
					tlsConn.TLSClientHello,
					tlsConn.TLSServerHello,
				)
				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
				ipv6 = NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				continue
			}

			// ChangeCipherSpec/Finishedを受信
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveChangeCipherSpecAndFinished(tcp) {
				tlsChangeCiperSpecAndFinished := ParsedTLSChangeCipherSpecAndFinished(tcp.Data, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.VerifingData())
				_ = tlsChangeCiperSpecAndFinished

				// TODO: 上のParsed内でserverからきたFinishedの検証してるけど、この辺りに持ってきた方がいいかも

				tlsConn.EstablishedConnection()

				// Finishedの検証が成功したので、以降からApplicationDataをやりとり
				tlsConn.ClientSequence++
				tlsApplicationData := NewTLSApplicationData(upperLayerData, tlsConn.KeyBlock, tlsConn.ClientSequence)

				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsApplicationData, tcp.Acknowledgment, tcp.Sequence)
				ipv6 = NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				// ここの EtherType は、ユーザー指定のを使う
				// TODO: 他のパケットもそうした方が良い？
				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, fEthrh.Typ, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tlsConn.SetState(TLSv12_STATE_SEND_APPLICATION_DATA)

				continue
			}

			// 送信した Application Data に対するレスポンスを受けて FinAck 送信
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsSendApplicationData() {
				// 受信した Application Data を復号
				lengthOfEncrypted := bytesToInt(tcp.Data[3:5])
				encrypted := tcp.Data[5 : 5+lengthOfEncrypted]
				decrypted := DecryptApplicationData(encrypted, tlsConn.KeyBlock, tlsConn.ClientSequence)
				// log.Printf("👺decrypted application data: %x, %s\n", decrypted, string(decrypted))
				_ = decrypted

				// TLS handshake の終了開始
				tlsConn.ClientSequence++
				tlsEncryptedAlert, _ := EncryptClientMessageForAlert(tlsConn.KeyBlock, tlsConn.ClientSequence, []byte{0x01, 0x00})
				tcp := NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsEncryptedAlert, tcp.Acknowledgment, tcp.Sequence)
				ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				// 続けてFinAck
				tcp = NewTCPFinAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence+uint32(len(tcp.Data)), tcp.Acknowledgment)
				ipv6 = NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				continue
			}

			if tcpConn.IsPassiveFinAck(tcp) {
				// それにack
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv6 := NewIPv6(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tlsConn.Close()
				tcpConn.Close()
				return nil
			}
		}
	}

	return nil
}
