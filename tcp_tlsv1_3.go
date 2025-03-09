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
			// recieved := make([]byte, 1500)
			recieved := make([]byte, 2000) // TODO: ここインターフェースのmtuでなくていいの？
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
				if n > 1500 {
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

				recieved := make([]byte, 2000)
				n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
				if err != nil {
					if n == -1 {
						continue
					}
					return err
				}
				eth := ParsedEthernetFrame(recieved[:n])
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

func tryEstablishTLS13Handshake(tlsConn *TLSv12Connection, serverHelloTCP []byte, tcpConn *TCPConnection, tcp *TCP, srcIPAddr uint32, dstIPAddr uint32, dstMACAddr HardwareAddr, srcMACAddr HardwareAddr, ethrhTyp uint16, nw *NetworkInterface) (prevTCP *TCP, err error) {
	tlsConn.currentHandshake = true
	tlsConn.TLSServerHelloFor1_3 = ParsedTLSServerHelloFor1_3(serverHelloTCP)
	tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, tlsConn.TLSServerHelloFor1_3.ServerHello.HandshakeProtocol.Bytes(true)...)
	serverKeyShare := tlsConn.TLSServerHelloFor1_3.GetServerKeyShare()
	// クライアントの秘密鍵とサーバの公開鍵で共通鍵を生成する ref: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/example/tls13_handshake.go#L69
	sharedKey, err := curve25519.X25519(tlsConn.ECDHEKeys.PrivateKey, serverKeyShare)
	if err != nil {
		return nil, err
	}
	tlsConn.KeyscheduleToMasterSecret(sharedKey)

	// fmt.Printf("👍👍length:%d\n", len(tlsConn.TLSServerHelloFor1_3.ApplicationDataProtocols))

	var publicKey *rsa.PublicKey
END:
	for _, adp := range tlsConn.TLSServerHelloFor1_3.ApplicationDataProtocols {
		plaintext := DecryptChacha20(adp.RecordLayer.Bytes(), adp.EncryptedApplicationData, tlsConn)
		plaintext = plaintext[0 : len(plaintext)-1] // ここなんで最後抜かすのかわかってない. Finished の検証通すまで時間かかった...

		switch plaintext[0] {
		case 0x08: // HandshakeTypeEncryptedExtensions
			// fmt.Printf("☆☆☆ EncryptedExtensions\n")

		case 0x0b: // HandshakeTypeCertificate
			// fmt.Printf("☆☆☆ Certificate\n")

			cert := &Certificate{
				Certificates: plaintext[8:], // TODO: certificate length まで見越してValidateメソッド内で処理してしまってる
			}
			if err := cert.Validate(); err != nil {
				return nil, err
			}
			publicKey = cert.ServerPublicKey()
			if publicKey == nil {
				return nil, fmt.Errorf("failed to parse server public key\n")
			}

		case 0x0f: // HandshakeTypeCertificateVerify
			// fmt.Printf("☆☆☆ CertificateVerify\n")

			cv := &CertificateVerify{
				HandshakeType:           plaintext[0],
				Length:                  plaintext[1:4],
				SignatureHashAlgorithms: plaintext[4:6],
				SignatureLength:         plaintext[6:8],
				Signature:               plaintext[8:],
			}
			// fmt.Printf("👺👺 SignatureHashAlgorithms: %x\n", cv.SignatureHashAlgorithms) // 0804. 08: rsa_pss_rsae_sha256 を表す。RSA-PSS 署名アルゴリズムと RSA 暗号化を組み合わせたもの / 04: sha256 を表す。SHA-256 ハッシュ関数が使用されたことを示す / サーバーが、RSA-PSS 署名アルゴリズムと SHA-256 ハッシュ関数を使用して署名を生成したことを意味する
			// fmt.Printf("👺👺 SignatureLength: %d\n", bytesToInt(cv.SignatureLength))     // len: 256
			// fmt.Printf("👺👺 Signature: %x\n", cv.Signature)                             // len: 257. 256より長いのは、padding分みたい

			if err := cv.VerifyServerCertificate(publicKey, tlsConn.handshakeMessages); err != nil {
				return nil, err
			}

		case 0x14: // HandshakeTypeFinished
			// fmt.Printf("☆☆☆ Finished\n")
			f := &FinishedMessage{
				HandshakeType: plaintext[0],
				Length:        plaintext[1:4],
				VerifyData:    plaintext[4:],
			}

			key := tlsConn.KeyBlockForTLSv13.ServerFinishedKey
			mac := hmac.New(sha256.New, key)
			mac.Write(WriteHash((tlsConn.handshakeMessages)))
			verifydata := mac.Sum(nil)

			if bytes.Equal(verifydata, f.VerifyData) {
				// fmt.Println("Server Verify data is correct !!")
				tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
				tlsConn.ServerHandshakeSeq++
				break END
			} else {
				return nil, fmt.Errorf("require send decrypt_error")
			}
		}
		tlsConn.handshakeMessages = append(tlsConn.handshakeMessages, plaintext...)
		tlsConn.ServerHandshakeSeq++
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
		return nil, err
	}

	tlsConn.currentHandshake = false
	tlsConn.EstablishedConnection()

	return tcp, nil
}

func SendEncryptedApplicationData(upperLayerData []byte, prevTCP *TCP, srcIPAddr uint32, dstIPAddr uint32, dstMACAddr HardwareAddr, srcMACAddr HardwareAddr, fEthrh *EthernetHeader, nw *NetworkInterface, tlsConn *TLSv12Connection, tcpConn *TCPConnection) error {
	rawFinMessage := append(upperLayerData, TLS_CONTENT_TYPE_APPLICATION_DATA)
	encryptedMessage := EncryptChacha20(rawFinMessage, tlsConn)

	tcp := NewTCPWithData(tcpConn.SrcPort, tcpConn.DstPort, encryptedMessage, prevTCP.Sequence+uint32(len(prevTCP.Data)), prevTCP.Acknowledgment)
	ipv4 := NewIPv4(IPv4_PROTO_TCP, srcIPAddr, dstIPAddr)
	tcp.CalculateChecksum(ipv4)

	ipv4.Data = tcp.Bytes()
	ipv4.CalculateTotalLength()
	ipv4.CalculateChecksum()

	ethernetFrame := NewEthernetFrame(dstMACAddr, srcMACAddr, fEthrh.Typ, ipv4.Bytes())
	if err := nw.Send(ethernetFrame); err != nil {
		return err
	}
	tlsConn.ClientAppSeq++

	return nil
}
