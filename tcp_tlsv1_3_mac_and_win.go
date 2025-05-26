//go:build darwin || windows
// +build darwin windows

package packemon

import (
	"context"
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// TCP 3way handshake と TLSv1.3 の handshake 後にリクエストする関数
func EstablishTCPTLSv1_3AndSendPayload(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
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

	tlsConn := NewTLSv13Connection()

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

			if (tcpConn.IsPassiveAck(tcp) || tcpConn.IsPassivePshAck(tcp)) && !tlsConn.IsEstablished() {
				// 単なるackメッセージの場合
				if len(tcp.Data) == 0 {
					continue
				}

				// これまでServer Helloを受信したことも含む
				if !tlsConn.IsPassiveServerHello(tcp) {
					continue
				}

				// 上の方で受信してるバイト数. 1500バイトより受信してるということは、Application Data Protocol が4つあると見做す
				// ただ、サーバ証明書のサイズが大きい場合(?)、これは破綻しそう
				if len(received) > 1500 {
					// それにack
					tcpForAck := NewTCPAckForPassiveData(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment, len(tcp.Data))
					ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
					tcpForAck.CalculateChecksum(ipv4)

					ipv4.Data = tcpForAck.Bytes()
					ipv4.CalculateTotalLength()
					ipv4.CalculateChecksum()

					ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
					if err := nw.Send(ethernetFrame); err != nil {
						return err
					}

					prevTCP, err := tryEstablishTLS13Handshake(tlsConn, tcp.Data, tcpConn, tcp, fIpv4.SrcAddr, fIpv4.DstAddr, fEthrh.Dst, fEthrh.Src, fEthrh.Typ, nw)
					if err != nil {
						return err
					}

					if tlsConn.IsEstablished() {
						// データ送信
						if err := SendEncryptedApplicationData(upperLayerData, prevTCP, srcIPAddr, dstIPAddr, dstMACAddr, srcMACAddr, fEthrh, nw, tlsConn, tcpConn); err != nil {
							return err
						}
					}

					continue
				}

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
				if ipv4.Protocol != IPv4_PROTO_TCP {
					continue
				}
				t := ParsedTCP(ip.Data)

				if tcpConn.IsPassivePshAck(t) {
					// それにack
					tcpForAck := NewTCPAckForPassiveData(tcpConn.SrcPort, tcpConn.DstPort, t.Sequence, t.Acknowledgment, len(t.Data))
					ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
					tcpForAck.CalculateChecksum(ipv4)

					ipv4.Data = tcpForAck.Bytes()
					ipv4.CalculateTotalLength()
					ipv4.CalculateChecksum()

					ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
					if err := nw.Send(ethernetFrame); err != nil {
						return err
					}

					tmp1 := tcp.Data
					tmp2 := t.Data
					tmp1 = append(tmp1, tmp2...)

					prevTCP, err := tryEstablishTLS13Handshake(tlsConn, tmp1, tcpConn, t, fIpv4.SrcAddr, fIpv4.DstAddr, fEthrh.Dst, fEthrh.Src, fEthrh.Typ, nw)
					if err != nil {
						return err
					}

					if tlsConn.IsEstablished() {
						// データ送信
						if err := SendEncryptedApplicationData(upperLayerData, prevTCP, srcIPAddr, dstIPAddr, dstMACAddr, srcMACAddr, fEthrh, nw, tlsConn, tcpConn); err != nil {
							return err
						}
					}

					continue
				}

				continue
			}

			// tls1.3のハンドシェイク後かつクライアントからリクエストした後の、サーバからのレスポンスを受信 & Close
			if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsEstablished() {
				if tlsConn.ServerAppSeq > 0 {
					// とりあえず、１回はサーバレスポンスの復号はできたので、continue して対向のFinAckを待つ
					continue
				}
				plaintext := DecryptChacha20(tcp.Data[0:5], tcp.Data[5:], tlsConn)
				_ = plaintext
				// ここで復号されたレスポンスが確認できた
				// fmt.Printf("decrypted: %s\n", plaintext)
				tlsConn.ServerAppSeq++

				// tcp rst でも送りたい、が
				return nil
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
