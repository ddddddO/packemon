package packemon

import (
	"bytes"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

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
