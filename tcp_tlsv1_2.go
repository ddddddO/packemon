package packemon

import (
	"bytes"
	"context"

	"golang.org/x/sys/unix"
)

// TCP 3way handshake と TLSv1.2 の handshake 後にリクエストする関数
func EstablishTCPTLSv1_2AndSendPayload(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
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
	tlsClientHello := NewTLSClientHello()
	var tlsServerHello *TLSServerHello
	var tlsClientKeyExchange *TLSClientKeyExchange
	var tlsClientFinished []byte

	var keyblock *KeyBlock
	var clientSequence int
	var master []byte

	for {
		recieved := make([]byte, 1500)
		n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
		if err != nil {
			if n == -1 {
				continue
			}
			return err
		}

		ethernetFrame := ParsedEthernetFrame(recieved)
		if ethernetFrame.Header.Typ != ETHER_TYPE_IPv4 {
			continue
		}

		ipv4 := ParsedIPv4(ethernetFrame.Data)
		if ipv4.Protocol != IPv4_PROTO_TCP {
			continue
		}

		tcp := ParsedTCP(ipv4.Data)
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
			if err := SendTLSClientHello(nw, tlsClientHello, tcpConn.SrcPort, tcpConn.DstPort, srcIPAddr, dstIPAddr, dstMACAddr, tcp.Sequence, tcp.Acknowledgment); err != nil {
				return err
			}

			continue
		}

		// ServerHello/Certificate/ServerHelloDone がセグメント分割されたパケットで届くことが多々あるため、このブロック内で連続して受信している
		// TODO: (10)443ポートがdstで絞った方がいいかも
		if tcpConn.IsPassiveAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
			for {
				recieved := make([]byte, 1500)
				n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
				if err != nil {
					if n == -1 {
						continue
					}
					return err
				}
				eth := ParsedEthernetFrame(recieved)
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

					tlsServerHello = ParsedTLSServerHello(mergedTCPData)
					if err := tlsServerHello.Certificate.Validate(); err != nil {
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
					tlsClientKeyExchange, keyblock, clientSequence, master, tlsClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
						tlsClientHello,
						tlsServerHello,
					)
					tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
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
		// TODO: (10)443ポートがdstで絞った方がいいかも
		// SeverHello(0x02)
		if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
			// TODO: server から、ServerHello/Certificate/ServerHelloDone でひとまとまりで返ってくればパースできるが、ServerHello と Certificate/ServerHelloDone がわかれて返ってくることがある。それで失敗してるよう？
			// 分かれてるとき、ServerHello はフラグが ACK だけど、分かれてないとき PSH/ACK
			//  <- そうでもなかった、環境によるみたい。example.com にリクエストすると ServerHello 単体パケットで PSH/ACK
			tlsServerHello = ParsedTLSServerHello(tcp.Data)
			if err := tlsServerHello.Certificate.Validate(); err != nil {
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
			tlsClientKeyExchange, keyblock, clientSequence, master, tlsClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
				tlsClientHello,
				tlsServerHello,
			)
			tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
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
		// TODO: (10)443ポートがdstとかもっと絞った方がいいかも
		if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveChangeCipherSpecAndFinished(tcp) {
			verifingData := &ForVerifing{
				Master:            master,
				ClientHello:       tlsClientHello,
				ServerHello:       tlsServerHello,
				ClientKeyExchange: tlsClientKeyExchange.ClientKeyExchange,
				ClientFinished:    tlsClientFinished,
			}
			tlsChangeCiperSpecAndFinished := ParsedTLSChangeCipherSpecAndFinished(tcp.Data, keyblock, clientSequence, verifingData)
			_ = tlsChangeCiperSpecAndFinished

			// TODO: 上のParsed内でserverからきたFinishedの検証してるけど、この辺りに持ってきた方がいいかも

			// Finishedの検証が成功したので、以降からApplicationDataをやりとり
			clientSequence++
			tlsApplicationData := NewTLSApplicationData(upperLayerData, keyblock, clientSequence)

			tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsApplicationData, tcp.Acknowledgment, tcp.Sequence)
			ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
			tcp.CalculateChecksum(ipv4)

			ipv4.Data = tcp.Bytes()
			ipv4.CalculateTotalLength()
			ipv4.CalculateChecksum()

			ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
			if err := nw.Send(ethernetFrame); err != nil {
				return err
			}

			// TODO: 本当なら Application Data 送ったあとにまた向こうからそのレスポンス（Application Data）を受けた後に finack しないといけない
			//       現状、リクエスト続けてる

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
			tcpConn.Close()
			return nil
		}
	}

	return nil
}

func SendTLSClientHello(nw *NetworkInterface, clientHello *TLSClientHello, srcPort, dstPort uint16, srcIPAddr uint32, dstIPAddr uint32, firsthopMACAddr [6]byte, prevSequence uint32, prevAcknowledgment uint32) error {
	tcp := NewTCPWithData(srcPort, dstPort, clientHello.Bytes(), prevSequence, prevAcknowledgment)
	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	dstMACAddr := HardwareAddr(firsthopMACAddr)
	srcMACAddr := HardwareAddr(nw.Intf.HardwareAddr)
	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
	return nw.Send(ethernetFrame)
}
