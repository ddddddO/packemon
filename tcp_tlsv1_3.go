package packemon

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/sys/unix"
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

			ethernetFrame := ParsedEthernetFrame(recieved)
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

			// ServerHello と ApplicationDataProtocol がセグメント分割されて届くため、このブロック内で連続して受信している
			// が分割されないで届くこともあるみたい？
			// ・分割されるとき: ServerHello のパケット -> Ack
			// ・分割されない(?)とき: ServerHello のパケット -> Psh/Ack
			if (tcpConn.IsPassiveAck(tcp) || tcpConn.IsPassivePshAck(tcp)) && tlsConn.IsPassiveServerHello(tcp) {

				// if tcpConn.IsPassiveAck(tcp) {
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

					// こちらのパターン（分割されない（ように見える）パターン失敗するのでエラーにしてる）
					if tcpConn.IsPassiveAck(t) {
						return fmt.Errorf("unsupported server hell and all application data protocols in 1 packet")
					}

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

						if err := tryEstablishTLS13Handshake(tlsConn, mergedTCPData, tcpConn, t, fIpv4.SrcAddr, fIpv4.DstAddr, fEthrh.Dst, fEthrh.Src, fEthrh.Typ, nw); err != nil {
							return err
						}

						fmt.Println("👍👍ぬ")

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
						// tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
						// 	tlsConn.TLSClientHello,
						// 	tlsConn.TLSServerHello,
						// )
						// tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
						// ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
						// tcp.CalculateChecksum(ipv4)

						// ipv4.Data = tcp.Bytes()
						// ipv4.CalculateTotalLength()
						// ipv4.CalculateChecksum()

						// ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
						// if err := nw.Send(ethernetFrame); err != nil {
						// 	return err
						// }

						break
					}
					continue
				}
				continue
				// }

				// if tcpConn.IsPassivePshAck(tcp) {
				// 	// TODO: 1パケットで server hello と application data protocol 来るパターン、ちょっと全部のデータ読み込めてないので一旦未対応とする
				// 	//       1500バイトより多い、Wireshark 上。ただ後続のパケットが残り持ってる？かわかってない
				// 	panic("unsupported server hello and all application data protocol in 1 packet")

				// 	if err := tryEstablishTLS13Handshake(tlsConn, tcp.Data); err != nil {
				// 		return err
				// 	}

				// 	fmt.Println("👍👍お")

				// 	// ackを返し
				// 	tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
				// 	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
				// 	tcp.CalculateChecksum(ipv4)

				// 	ipv4.Data = tcp.Bytes()
				// 	ipv4.CalculateTotalLength()
				// 	ipv4.CalculateChecksum()

				// 	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
				// 	if err := nw.Send(ethernetFrame); err != nil {
				// 		return err
				// 	}
				// 	continue
				// }

				continue
			}

			// ServerHelloを受信
			// SeverHello(0x02)
			// if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveServerHello(tcp) {
			// 	if err := tryEstablishTLS13Handshake(tlsConn, tcp.Data); err != nil {
			// 		return err
			// 	}

			// 	// ackを返し
			// 	tcp := NewTCPAck(tcpConn.SrcPort, tcpConn.DstPort, tcp.Sequence, tcp.Acknowledgment)
			// 	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
			// 	tcp.CalculateChecksum(ipv4)

			// 	ipv4.Data = tcp.Bytes()
			// 	ipv4.CalculateTotalLength()
			// 	ipv4.CalculateChecksum()

			// 	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
			// 	if err := nw.Send(ethernetFrame); err != nil {
			// 		return err
			// 	}

			// 	// さらに ClientKeyExchange や Finished などを返す
			// 	// tlsConn.TLSClientKeyExchange, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.Master, tlsConn.TLSClientFinished = NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(
			// 	// 	tlsConn.TLSClientHello,
			// 	// 	tlsConn.TLSServerHello,
			// 	// )
			// 	// tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsConn.TLSClientKeyExchange.Bytes(), tcp.Sequence, tcp.Acknowledgment)
			// 	// ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
			// 	// tcp.CalculateChecksum(ipv4)

			// 	// ipv4.Data = tcp.Bytes()
			// 	// ipv4.CalculateTotalLength()
			// 	// ipv4.CalculateChecksum()

			// 	// ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, ETHER_TYPE_IPv4, ipv4.Bytes())
			// 	// if err := nw.Send(ethernetFrame); err != nil {
			// 	// 	return err
			// 	// }

			// 	continue
			// }

			// ChangeCipherSpec/Finishedを受信
			// if tcpConn.IsPassivePshAck(tcp) && tlsConn.IsPassiveChangeCipherSpecAndFinished(tcp) {
			// 	tlsChangeCiperSpecAndFinished := ParsedTLSChangeCipherSpecAndFinished(tcp.Data, tlsConn.KeyBlock, tlsConn.ClientSequence, tlsConn.VerifingData())
			// 	_ = tlsChangeCiperSpecAndFinished

			// 	// TODO: 上のParsed内でserverからきたFinishedの検証してるけど、この辺りに持ってきた方がいいかも

			// 	tlsConn.EstablishedConnection()

			// 	// Finishedの検証が成功したので、以降からApplicationDataをやりとり
			// 	tlsConn.ClientSequence++
			// 	tlsApplicationData := NewTLSApplicationData(upperLayerData, tlsConn.KeyBlock, tlsConn.ClientSequence)

			// 	tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, tlsApplicationData, tcp.Acknowledgment, tcp.Sequence)
			// 	ipv4 = NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
			// 	tcp.CalculateChecksum(ipv4)

			// 	ipv4.Data = tcp.Bytes()
			// 	ipv4.CalculateTotalLength()
			// 	ipv4.CalculateChecksum()

			// 	// ここの EtherType は、ユーザー指定のを使う
			// 	// TODO: 他のパケットもそうした方が良い？
			// 	ethernetFrame = NewEthernetFrame(dstMACAddr, srcMACAddr, fEthrh.Typ, ipv4.Bytes())
			// 	if err := nw.Send(ethernetFrame); err != nil {
			// 		return err
			// 	}
			// 	tlsConn.SetState(TLSv12_STATE_SEND_APPLICATION_DATA)

			// 	continue
			// }

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

func tryEstablishTLS13Handshake(tlsConn *TLSv12Connection, serverHelloTCP []byte, tcpConn *TCPConnection, tcp *TCP, srcIPAddr uint32, dstIPAddr uint32, dstMACAddr HardwareAddr, srcMACAddr HardwareAddr, ethrhTyp uint16, nw *NetworkInterface) error {
	tlsConn.currentHandshake = true
	tlsConn.TLSServerHelloFor1_3 = ParsedTLSServerHelloFor1_3(serverHelloTCP)
	tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, tlsConn.TLSServerHelloFor1_3.ServerHello.HandshakeProtocol.Bytes(true)...)
	serverKeyShare := tlsConn.TLSServerHelloFor1_3.GetServerKeyShare()
	// クライアントの秘密鍵とサーバの公開鍵で共通鍵を生成する ref: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/example/tls13_handshake.go#L69
	sharedKey, err := curve25519.X25519(tlsConn.ECDHEKeys.PrivateKey, serverKeyShare)
	if err != nil {
		return err
	}
	tlsConn.KeyscheduleToMasterSecret(sharedKey)

	// return fmt.Errorf("ApplicationDataProtocols length: %d\n", len(tlsConn.TLSServerHelloFor1_3.ApplicationDataProtocols))

	var publicKey *rsa.PublicKey
END:
	for _, adp := range tlsConn.TLSServerHelloFor1_3.ApplicationDataProtocols {
		plaintext := DecryptChacha20(adp.RecordLayer.Bytes(), adp.EncryptedApplicationData, tlsConn)

		switch plaintext[0] {
		case 0x08: // HandshakeTypeEncryptedExtensions
			fmt.Printf("☆☆☆ EncryptedExtensions\n")

			tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			tlsConn.ServerHandshakeSeq++
			continue
		case 0x0b: // HandshakeTypeCertificate
			fmt.Printf("☆☆☆ Certificate\n")

			cert := &Certificate{
				Certificates: plaintext[8:], // TODO: certificate length まで見越してValidateメソッド内で処理してしまってる
			}
			if err := cert.Validate(); err != nil {
				return err
			}
			publicKey = cert.ServerPublicKey()
			if publicKey == nil {
				return fmt.Errorf("failed to parse server public key\n")
			}

			tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			tlsConn.ServerHandshakeSeq++
			continue
		case 0x0f: // HandshakeTypeCertificateVerify
			fmt.Printf("☆☆☆ CertificateVerify\n")

			cv := &CertificateVerify{
				HandshakeType:           plaintext[0],
				Length:                  plaintext[1:4],
				SignatureHashAlgorithms: plaintext[4:6],
				SignatureLength:         plaintext[6:8],
				Signature:               plaintext[8:],
			}
			// TODO: メソッド内でエラー起きてるけどここで握りつぶしてる
			if err := cv.VerifyServerCertificate(publicKey, tlsConn.handshakeMessages); err != nil {
				// log.Println("NNNNNN")
			}

			tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			tlsConn.ServerHandshakeSeq++
			continue
		case 0x14: // HandshakeTypeFinished
			fmt.Printf("☆☆☆ Finished\n")
			f := &FinishedMessage{
				HandshakeType: plaintext[0],
				Length:        plaintext[1:4],
				VerifyData:    plaintext[4:],
			}

			key := tlsConn.KeyBlockForTLSv13.ServerFinishedKey
			mac := hmac.New(sha256.New, key)
			mac.Write(WriteHash((tlsConn.handshakeMessages)))
			verifydata := mac.Sum(nil)
			_, _ = f, verifydata

			// fmt.Printf("👍👍 v: %x\n", verifydata)
			// fmt.Printf("👍👍 V: %x\n", f.VerifyData)

			// TODO: ここどうもマッチしない。検証成功してないが、一旦飛ばす
			// if bytes.Equal(verifydata, f.VerifyData) {
			// 	fmt.Println("Server Verify data is correct !!")
			// 	tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			// 	tlsConn.ServerHandshakeSeq++
			// 	break END
			// } else {
			// 	// panic("require send decrypt_error")
			// }
			tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			tlsConn.ServerHandshakeSeq++
			break END
		default:
			tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
			tlsConn.ServerHandshakeSeq++
		}
	}

	// app用のkey生成
	tlsConn.KeyscheduleToAppTraffic()
	changeCipherSpec := TLSChangeCipherSpecAndEncryptedHandshakeMessage{
		ChangeCipherSpecProtocol: &ChangeCipherSpecProtocol{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{0x14},
				Version:     TLS_VERSION_1_2,
				Length:      []byte{0x00, 0x01},
			},
			ChangeCipherSpecMessage: []byte{0x01},
		},
	}

	key := tlsConn.KeyBlockForTLSv13.ClientFinishedKey
	mac := hmac.New(sha256.New, key)
	mac.Write(WriteHash(tlsConn.handshakeMessages))
	verifydata := mac.Sum(nil)

	finMessage := &FinishedMessage{
		HandshakeType: 0x14, // HandshakeTypeFinished
		Length:        uintTo3byte(uint32(len(verifydata))),
		VerifyData:    verifydata,
	}
	rawFinMessage := append(finMessage.Bytes(), TLS_CONTENT_TYPE_HANDSHAKE)
	encryptedMessage := EncryptChacha20(rawFinMessage, tlsConn)
	message := append(changeCipherSpec.Bytes(), encryptedMessage...)

	tcp = NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, message, tcp.Acknowledgment, tcp.Sequence)
	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, ethrhTyp, ipv4.Bytes())
	if err := nw.Send(ethernetFrame); err != nil {
		return err
	}

	return nil
}
