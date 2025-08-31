//go:build linux
// +build linux

package packemon

import (
	"bytes"
	"context"
	"fmt"

	"golang.org/x/sys/unix"
)

// このなかで、ログ出力などしないこと。Monitor の下に出てくる
// 挙動を詳細に確認する場合は、internal内の SendTCP3wayhandshake 関数でやること
// TODO: 対向からRST,RST/ACKが来た時にreturnするようにする
func EstablishConnectionAndSendPayloadXxx(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv4 *IPv4, fTcp *TCP, upperLayerData []byte) error {
	nw, err := NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	var srcIPAddr uint32 = fIpv4.SrcAddr
	var dstIPAddr uint32 = fIpv4.DstAddr
	dstMACAddr := fEthrh.Dst
	srcMACAddr := fEthrh.Src

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

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout!")

		default:
			recieved := make([]byte, 1500)
			n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
			if err != nil {
				if n == -1 {
					continue
				}
				return err
			}

			ethernetFrame := ParsedEthernetFrame(recieved[:n])
			if ethernetFrame.Header.Typ != ETHER_TYPE_IPv4 {
				continue
			}

			ipv4 := ParsedIPv4(ethernetFrame.Data)
			if ipv4.Protocol != IPv4_PROTO_TCP {
				continue
			}

			tcp := ParsedTCP(ipv4.Data)
			if tcpConn.IsPassiveSynAckForHandshake(tcp) {
				// log.Println("passive TCP_FLAGS_SYN_ACK")

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

				// L4より上位レイヤーのデータを送らずに3way handshakeだけしたい(でその後、サーバからデータ取得したい)みたいなことがあるため
				if len(upperLayerData) == 0 {
					continue
				}

				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, upperLayerData, tcp.Sequence, tcp.Acknowledgment)
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

			if tcpConn.IsPassiveAck(tcp) {
				// log.Println("passive TCP_FLAGS_ACK")
				continue
			}

			if tcpConn.IsPassivePshAck(tcp) {
				lineLength := bytes.Index(tcp.Data, []byte{0x0d, 0x0a}) // "\r\n"
				if lineLength == -1 {
					// log.Println("-1")
					continue
				}
				// log.Println("passive TCP_FLAGS_PSH_ACK")

				// HTTPレスポンス受信
				if tcp.SrcPort == PORT_HTTP {
					resp := ParsedHTTPResponse(tcp.Data)
					// log.Printf("%+v\n", resp)

					// そのackを返す
					tcp := NewTCPAckForPassiveData(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment, resp.Len())
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
					tcp = NewTCPFinAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
					ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
					tcp.CalculateChecksum(ipv4)

					ipv4.Data = tcp.Bytes()
					ipv4.CalculateTotalLength()
					ipv4.CalculateChecksum()

					ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
					if err := nw.Send(ethernetFrame); err != nil {
						return err
					}
				}
				continue
			}

			if tcpConn.IsPassiveFinAck(tcp) {
				// log.Println("passive TCP_FLAGS_FIN_ACK")

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

			continue
		}
	}
}

func EstablishConnectionAndSendPayloadXxxForIPv6(ctx context.Context, nwInterface string, fEthrh *EthernetHeader, fIpv6 *IPv6, fTcp *TCP, upperLayerData []byte) error {
	nw, err := NewNetworkInterface(nwInterface)
	if err != nil {
		return err
	}

	var srcIPAddr []uint8 = fIpv6.SrcAddr
	var dstIPAddr []uint8 = fIpv6.DstAddr
	dstMACAddr := fEthrh.Dst
	srcMACAddr := fEthrh.Src

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

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout!")

		default:
			recieved := make([]byte, 1500)
			n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
			if err != nil {
				if n == -1 {
					continue
				}
				return err
			}

			ethernetFrame := ParsedEthernetFrame(recieved[:n])
			if ethernetFrame.Header.Typ != ETHER_TYPE_IPv6 {
				continue
			}

			ipv6 := ParsedIPv6(ethernetFrame.Data)
			if ipv6.NextHeader != IPv4_PROTO_TCP {
				continue
			}

			tcp := ParsedTCP(ipv6.Data)
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

				// L4より上位レイヤーのデータを送らずに3way handshakeだけしたい(でその後、サーバからデータ取得したい)みたいなことがあるため
				if len(upperLayerData) == 0 {
					continue
				}

				tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, upperLayerData, tcp.Sequence, tcp.Acknowledgment)
				ipv6 = NewIPv6(IPv6_NEXT_HEADER_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}

				continue
			}

			if tcpConn.IsPassiveAck(tcp) {
				continue
			}

			if tcpConn.IsPassivePshAck(tcp) {
				lineLength := bytes.Index(tcp.Data, []byte{0x0d, 0x0a}) // "\r\n"
				if lineLength == -1 {
					// log.Println("-1")
					continue
				}
				// log.Println("passive TCP_FLAGS_PSH_ACK")

				// HTTPレスポンス受信
				if tcp.SrcPort == PORT_HTTP {
					resp := ParsedHTTPResponse(tcp.Data)
					// log.Printf("%+v\n", resp)

					// そのackを返す
					// log.Printf("Length of http resp: %d\n", resp.Len())

					tcp := NewTCPAckForPassiveData(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment, resp.Len())
					ipv6 := NewIPv6(IPv6_NEXT_HEADER_TCP, srcIPAddr, dstIPAddr)
					tcp.CalculateChecksumForIPv6(ipv6)

					ipv6.Data = tcp.Bytes()
					ipv6.PayloadLength = uint16(len(ipv6.Data))

					ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
					if err := nw.Send(ethernetFrame); err != nil {
						return err
					}

					// 続けてFinAck
					tcp = NewTCPFinAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
					ipv6 = NewIPv6(IPv6_NEXT_HEADER_TCP, srcIPAddr, dstIPAddr)
					tcp.CalculateChecksumForIPv6(ipv6)

					ipv6.Data = tcp.Bytes()
					ipv6.PayloadLength = uint16(len(ipv6.Data))

					ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
					if err := nw.Send(ethernetFrame); err != nil {
						return err
					}
				}
				continue
			}

			if tcpConn.IsPassiveFinAck(tcp) {
				// それにack
				tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				ipv6 := NewIPv6(IPv6_NEXT_HEADER_TCP, srcIPAddr, dstIPAddr)
				tcp.CalculateChecksumForIPv6(ipv6)

				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))

				ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv6, ipv6.Bytes())
				if err := nw.Send(ethernetFrame); err != nil {
					return err
				}
				tcpConn.Close()
				return nil
			}
		}
	}
}
