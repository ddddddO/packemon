package packemon

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"log"
)

func ParsedTLSToPassive(tcp *TCP, p *Passive) {
	// 以下、tcp.Data[1:3] にある(Record Layer) version あてにならないかも。tls version 1.0 の値でも wireshark 上で、tls1.2 or 1.3 の record という表示になってる
	// なので、HandshakeProtocol 内の、Version でも確認する
	// if bytes.Equal(TLS_VERSION_1_2, tcp.Data[1:3]) {

	// TODO: support TLSv1.3
	if bytes.Equal(TLS_VERSION_1_2, tcp.Data[9:11]) || bytes.Equal(TLS_VERSION_1_2, tcp.Data[1:3]) {
		// TLS の 先頭の Content Type をチェック
		// TODO: あくまで先頭の、なので、パケットが分割されて例えば、ChangeChiperSpec のみ来たりする可能性はあるかも
		switch tcp.Data[0] {
		case TLS_CONTENT_TYPE_HANDSHAKE:
			if tcp.Data[5] == TLS_HANDSHAKE_TYPE_CLIENT_HELLO {
				tlsClientHello := ParsedTLSClientHello(tcp.Data)
				p.TLSClientHello = tlsClientHello
				return
			}

			if tcp.Data[5] == TLS_HANDSHAKE_TYPE_SERVER_HELLO {
				tlsServerHello := ParsedTLSServerHello(tcp.Data)
				p.TLSServerHello = tlsServerHello
				return
			}

			if tcp.Data[5] == TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE {
				tlsClientKeyExchange := ParsedTLSClientKeyexchange(tcp.Data)
				p.TLSClientKeyExchange = tlsClientKeyExchange
				return
			}
		case TLS_HANDSHAKE_TYPE_CHANGE_CIPHER_SPEC:
			tlsChangeCipherSpecAndEncryptedHandshakeMessage := ParsedTLSChangeCipherSpecAndEncryptedHandshakeMessage(tcp.Data)
			p.TLSChangeCipherSpecAndEncryptedHandshakeMessage = tlsChangeCipherSpecAndEncryptedHandshakeMessage
			return
		case TLS_CONTENT_TYPE_APPLICATION_DATA:
			tlsApplicationData := ParsedTLSApplicationData(tcp.Data)
			p.TLSApplicationData = tlsApplicationData
			return
		case TLS_CONTENT_TYPE_ALERT:
			tlsEncryptedAlert := ParsedTLSEncryptedAlert(tcp.Data)
			p.TLSEncryptedAlert = tlsEncryptedAlert
			return
		default:

		}
	}
}

const TLS_CONTENT_TYPE_HANDSHAKE = 0x16
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14
const TLS_CONTENT_TYPE_APPLICATION_DATA = 0x17

// ref: https://tls12.xargs.org/#client-hello/annotated
// 以降のstructのフィールドはWiresharkを見つつ補完
type TLSRecordLayer struct {
	ContentType []byte
	Version     []byte
	Length      []byte
}

func (l *TLSRecordLayer) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, l.ContentType...)
	buf = append(buf, l.Version...)
	buf = append(buf, l.Length...)
	return buf
}

type TLSHandshakeProtocol struct {
	HandshakeType            []byte
	Length                   []byte
	Version                  []byte
	Random                   []byte
	SessionID                []byte
	CipherSuitesLength       []byte
	CipherSuites             []uint16 // ref: https://tls12.xargs.org/#client-hello/annotated [Ciper Suites]
	CompressionMethodsLength []byte
	CompressionMethods       []byte
	ExtensionsLength         []byte
	Extentions               []byte // サイト見ると結構種類有りそう
}

func (p *TLSHandshakeProtocol) Bytes(isFromServer bool) []byte {
	buf := []byte{}
	buf = append(buf, p.HandshakeType...)
	buf = append(buf, p.Length...)
	buf = append(buf, p.Version...)
	buf = append(buf, p.Random...)
	buf = append(buf, p.SessionID...)
	buf = append(buf, p.lengthCipherSuites(isFromServer)...)
	buf = append(buf, p.bytesCipherSuites()...)
	buf = append(buf, p.CompressionMethodsLength...)
	buf = append(buf, p.CompressionMethods...)
	buf = append(buf, p.ExtensionsLength...)
	buf = append(buf, p.Extentions...)
	return buf
}

func (p *TLSHandshakeProtocol) bytesCipherSuites() []byte {
	if len(p.CipherSuites) == 0 {
		return nil
	}
	buf := []byte{}
	for i := range p.CipherSuites {
		buf = binary.BigEndian.AppendUint16(buf, p.CipherSuites[i])
	}
	return buf
}

func (p *TLSHandshakeProtocol) lengthCipherSuites(isFromServer bool) []byte {
	if len(p.CipherSuites) == 0 || isFromServer {
		return nil
	}
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(p.CipherSuites)*2)) // 2byteなため×2
	return buf
}

type TLSClientHello struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

const TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_TYPE_SERVER_HELLO = 0x02
const COMPRESSION_METHOD_NULL = 0x00

var TLS_VERSION_1_2 = []byte{0x03, 0x03}

func NewTLSClientHello() *TLSClientHello {
	handshake := &TLSHandshakeProtocol{
		HandshakeType: []byte{TLS_HANDSHAKE_TYPE_CLIENT_HELLO},
		Length:        []byte{0x00, 0x00, 0x00}, // 後で計算して求めるが、初期化のため
		Version:       TLS_VERSION_1_2,
		Random:        make([]byte, 32), // 000000....
		SessionID:     []byte{0x00},
		// SessionID: make([]byte, 32),

		// TODO: あれ、ここにCipherSuitesLength指定しないでいいの？

		CipherSuites: []uint16{
			// tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			// tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,

			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,

			// tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			// tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			// tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			// tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
			// tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		},
		CompressionMethodsLength: []byte{0x00}, // 後で計算して求めるが、初期化のため
		CompressionMethods:       []byte{COMPRESSION_METHOD_NULL},
		ExtensionsLength:         []byte{0x00, 0x00}, // 後で計算して求めるが、初期化のため
		Extentions:               []byte{},
	}

	handshake.CompressionMethodsLength = []byte{byte(len(handshake.CompressionMethods))}
	tmp := &bytes.Buffer{}
	WriteUint16(tmp, uint16(len(handshake.Extentions))) // TODO: ここ実際にExtentions指定してないで実装したから、指定したらバグってるかも
	handshake.ExtensionsLength = tmp.Bytes()

	lengthAll := &bytes.Buffer{}
	isFromServer := false
	WriteUint16(lengthAll, uint16(len(handshake.Bytes(isFromServer))))

	// 全体の長さ - 4 でいいはず
	handshake.Length = uintTo3byte(uint32(len(handshake.Bytes(isFromServer))) - 4)

	return &TLSClientHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{TLS_CONTENT_TYPE_HANDSHAKE},
			Version:     TLS_VERSION_1_2,
			Length:      lengthAll.Bytes(),
		},
		HandshakeProtocol: handshake,
	}
}

func ParsedTLSClientHello(b []byte) *TLSClientHello {
	cipherSuitesLength := b[44:46]
	cipherSuites := []uint16{}
	// たぶん、2byteずつ増えていくでokと思うけど
	for i := 0; i < (bytesToInt(cipherSuitesLength) / 2); i++ {
		point := i * 2
		cipherSuite := binary.BigEndian.Uint16(b[46+point : 46+point+2])
		cipherSuites = append(cipherSuites, cipherSuite)
	}

	compressionMethodsLength := b[46+bytesToInt(cipherSuitesLength) : 47+bytesToInt(cipherSuitesLength)]
	extensionsLength := b[47+bytesToInt(cipherSuitesLength)+int(compressionMethodsLength[0]) : 47+bytesToInt(cipherSuitesLength)+int(compressionMethodsLength[0])+2]

	return &TLSClientHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      b[3:5],
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType:            []byte{b[5]},
			Length:                   b[6:9],
			Version:                  b[9:11],
			Random:                   b[11:43],
			SessionID:                []byte{b[43]},
			CipherSuitesLength:       cipherSuitesLength,
			CipherSuites:             cipherSuites,
			CompressionMethodsLength: compressionMethodsLength,
			CompressionMethods:       b[47+bytesToInt(cipherSuitesLength) : 47+bytesToInt(cipherSuitesLength)+int(compressionMethodsLength[0])],
			ExtensionsLength:         extensionsLength,
			Extentions:               b[47+bytesToInt(cipherSuitesLength)+int(compressionMethodsLength[0])+2 : 47+bytesToInt(cipherSuitesLength)+int(compressionMethodsLength[0])+2+bytesToInt(extensionsLength)],
		},
	}
}

// 2byteをintへ変換
func bytesToInt(b []byte) int {
	return int(b[0])<<8 + int(b[1])
}

// 3byteをintへ変換
func bytesToInt2(b []byte) int {
	return int(b[0])<<16 + int(b[1])<<8 + int(b[2])
}

func (tch *TLSClientHello) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, tch.RecordLayer.Bytes()...)
	isFromServer := false
	buf = append(buf, tch.HandshakeProtocol.Bytes(isFromServer)...)
	return buf
}

type TLSServerHello struct {
	ServerHello     *ServerHello
	Certificate     *Certificate
	ServerHelloDone *ServerHelloDone
}

func (tlsserverhello *TLSServerHello) Bytes() []byte {
	b := []byte{}
	b = append(b, tlsserverhello.ServerHello.Bytes()...)
	b = append(b, tlsserverhello.Certificate.Bytes()...)
	b = append(b, tlsserverhello.ServerHelloDone.Bytes()...)
	return b
}

type ServerHello struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

func (s *ServerHello) Bytes() []byte {
	b := []byte{}
	b = append(b, s.RecordLayer.Bytes()...)
	isFromServer := true
	b = append(b, s.HandshakeProtocol.Bytes(isFromServer)...)
	return b
}

type Certificate struct {
	RecordLayer        *TLSRecordLayer
	HandshakeProtocol  *TLSHandshakeProtocol
	CertificatesLength []byte
	Certificates       []byte // TODO: ここ更にフィールドあった

	certs []*x509.Certificate // parse成功した証明書を格納する
}

func (c *Certificate) Bytes() []byte {
	b := []byte{}
	b = append(b, c.RecordLayer.Bytes()...)
	isFromServer := true
	b = append(b, c.HandshakeProtocol.Bytes(isFromServer)...)
	b = append(b, c.CertificatesLength...)
	b = append(b, c.Certificates...)
	return b
}

// ref: https://zenn.dev/satoken/articles/golang-tls1_2#serverhello%2C-certificate%2C-serverhellodone
func (c *Certificate) Validate() error {
	// log.Printf("validation cert: \n%x\n", c.Certificates[3:])
	certs, err := x509.ParseCertificates(c.Certificates[3:]) // TODO: 最初の3byteはCertificate Length
	if err != nil {
		log.Println(err)
		return err
	}
	log.Printf("certificate num: %d\n", len(certs))
	c.certs = certs

	ospool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	log.Println("start verify server certificate")
	for i := len(c.certs) - 1; i >= 0; i-- {
		opts := x509.VerifyOptions{}
		if len(c.certs[i].DNSNames) == 0 {
			opts.Roots = ospool
		} else {
			opts.Roots = ospool
			opts.DNSName = c.certs[i].DNSNames[0]

			log.Printf("\tDNS name in server certificate: %s\n", c.certs[i].DNSNames[0])
		}

		if _, err := c.certs[i].Verify(opts); err != nil {
			log.Printf("\tfailed to verify server certificate: %s\n", err)
			// return err

			// TODO: 以下対応までエラーとしないようにする
			// https://github.com/ddddddO/packemon/issues/63
		}
		if i > 0 {
			ospool.AddCert(c.certs[1])
		}
	}
	log.Println("finish verify server certificate")
	return nil
}

func (c *Certificate) ServerPublicKey() *rsa.PublicKey {
	if len(c.certs) == 0 {
		log.Println("nil ServerPublicKey")
		return nil
	}
	pub, ok := c.certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		log.Printf("not public key")
		return nil
	}
	return pub
}

type ServerHelloDone struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

func (sd *ServerHelloDone) Bytes() []byte {
	b := []byte{}
	b = append(b, sd.RecordLayer.Bytes()...)
	isFromServer := true
	b = append(b, sd.HandshakeProtocol.Bytes(isFromServer)...)
	return b
}

func ParsedTLSServerHello(b []byte) *TLSServerHello {
	slength := b[3:5]
	serverHello := &ServerHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      slength,
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType:      []byte{b[5]},
			Length:             b[6:9],
			Version:            b[9:11],
			Random:             b[11:43],
			SessionID:          []byte{b[43]},
			CipherSuites:       []uint16{parsedCipherSuites(b[44:46])},
			CompressionMethods: []byte{b[46]},
		},
	}
	nextPosition := 47
	if bytesToInt(slength) > 42 {
		extentionsLength := b[nextPosition : nextPosition+2]
		serverHello.HandshakeProtocol.ExtensionsLength = extentionsLength

		nextPosition += 2
		serverHello.HandshakeProtocol.Extentions = b[nextPosition : nextPosition+bytesToInt(extentionsLength)]
		nextPosition += bytesToInt(extentionsLength)
	}

	certificate := &Certificate{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPosition]},
			Version:     b[nextPosition+1 : nextPosition+3],
			Length:      b[nextPosition+3 : nextPosition+5],
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{b[nextPosition+5]},
			Length:        b[nextPosition+6 : nextPosition+9],
		},
		CertificatesLength: b[nextPosition+9 : nextPosition+12],
	}
	certificateLength := parsedCertificatesLength(b[nextPosition+9 : nextPosition+12])
	certificate.Certificates = b[nextPosition+12 : nextPosition+12+certificateLength]
	nextPosition += 12 + certificateLength

	serverHelloDone := &ServerHelloDone{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPosition]},
			Version:     b[nextPosition+1 : nextPosition+3],
			Length:      b[nextPosition+3 : nextPosition+5],
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{b[nextPosition+5]},
			Length:        b[nextPosition+6 : nextPosition+9],
		},
	}

	return &TLSServerHello{
		ServerHello:     serverHello,
		Certificate:     certificate,
		ServerHelloDone: serverHelloDone,
	}
}

func parsedCipherSuites(b []byte) uint16 {
	if bytes.Equal(b, []byte{0x00, 0x9c}) {
		return tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	}

	log.Printf("TLS not parsed CipherSuites: %x\n", b)
	return tls.TLS_RSA_WITH_AES_128_GCM_SHA256
}

func parsedCertificatesLength(b []byte) int {
	b = append([]byte{0x00}, b...)
	return int(binary.BigEndian.Uint32(b))
}

type TLSClientKeyExchange struct {
	ClientKeyExchange         *ClientKeyExchange
	ChangeCipherSpecProtocol  *ChangeCipherSpecProtocol
	EncryptedHandshakeMessage []byte
}

func ParsedTLSClientKeyexchange(b []byte) *TLSClientKeyExchange {
	encryptedPreMasterLength := b[9:11]
	clientKeyExchange := &ClientKeyExchange{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      b[3:5],
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{b[5]},
			Length:        b[6:9],
		},
		RSAEncryptedPreMasterSecret: &RSAEncryptedPreMasterSecret{
			EncryptedPreMasterLength: encryptedPreMasterLength,
		},
	}
	nextPosition := 11
	clientKeyExchange.RSAEncryptedPreMasterSecret.EncryptedPreMaster = b[nextPosition : nextPosition+bytesToInt(encryptedPreMasterLength)]
	nextPosition += bytesToInt(encryptedPreMasterLength)

	lengthOfChangeCipherSpecProtocol := b[nextPosition+3 : nextPosition+5]
	changeCipherSpecProtocol := &ChangeCipherSpecProtocol{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPosition]},
			Version:     b[nextPosition+1 : nextPosition+3],
			Length:      lengthOfChangeCipherSpecProtocol,
		},
		ChangeCipherSpecMessage: b[nextPosition+5 : nextPosition+5+bytesToInt(lengthOfChangeCipherSpecProtocol)],
	}
	nextPosition += 5 + bytesToInt(lengthOfChangeCipherSpecProtocol)

	lengthOfEncryptedHandshakeMessage := b[nextPosition+3 : nextPosition+5]
	encryptedHandshakeMessage := &EncryptedHandshakeMessage{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPosition]},
			Version:     b[nextPosition+1 : nextPosition+3],
			Length:      lengthOfEncryptedHandshakeMessage,
		},
		EncryptedHandshakeMessage_: b[nextPosition+5 : nextPosition+5+bytesToInt(lengthOfEncryptedHandshakeMessage)],
	}

	return &TLSClientKeyExchange{
		ClientKeyExchange:         clientKeyExchange,
		ChangeCipherSpecProtocol:  changeCipherSpecProtocol,
		EncryptedHandshakeMessage: encryptedHandshakeMessage.Bytes(),
	}

}

func (tlsclientkeyexchange *TLSClientKeyExchange) Bytes() []byte {
	b := []byte{}
	b = append(b, tlsclientkeyexchange.ClientKeyExchange.Bytes()...)
	b = append(b, tlsclientkeyexchange.ChangeCipherSpecProtocol.Bytes()...)
	b = append(b, tlsclientkeyexchange.EncryptedHandshakeMessage...)
	return b
}

type ClientKeyExchange struct {
	RecordLayer                 *TLSRecordLayer
	HandshakeProtocol           *TLSHandshakeProtocol
	RSAEncryptedPreMasterSecret *RSAEncryptedPreMasterSecret
}

type RSAEncryptedPreMasterSecret struct {
	EncryptedPreMasterLength []byte
	EncryptedPreMaster       []byte
}

func (r *RSAEncryptedPreMasterSecret) Bytes() []byte {
	b := []byte{}
	b = append(b, r.EncryptedPreMasterLength...)
	b = append(b, r.EncryptedPreMaster...)
	return b
}

func (c *ClientKeyExchange) Bytes() []byte {
	b := []byte{}
	b = append(b, c.RecordLayer.Bytes()...)
	isFromServer := false
	b = append(b, c.HandshakeProtocol.Bytes(isFromServer)...)
	b = append(b, c.RSAEncryptedPreMasterSecret.Bytes()...)
	return b
}

type ChangeCipherSpecProtocol struct {
	RecordLayer             *TLSRecordLayer
	ChangeCipherSpecMessage []byte
}

func (cc *ChangeCipherSpecProtocol) Bytes() []byte {
	b := []byte{}
	b = append(b, cc.RecordLayer.Bytes()...)
	b = append(b, cc.ChangeCipherSpecMessage...)
	return b
}

type EncryptedHandshakeMessage struct {
	RecordLayer                *TLSRecordLayer
	EncryptedHandshakeMessage_ []byte
}

func (e *EncryptedHandshakeMessage) Bytes() []byte {
	b := []byte{}
	b = append(b, e.RecordLayer.Bytes()...)
	b = append(b, e.EncryptedHandshakeMessage_...)
	return b
}

const TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = 0x10
const TLS_HANDSHAKE_TYPE_CHANGE_CIPHER_SPEC = 0x14
const TLS_HANDSHAKE_TYPE_FINISHED = 0x14

func NewTLSClientKeyExchangeAndChangeCipherSpecAndFinished(clientHello *TLSClientHello, serverHello *TLSServerHello) (*TLSClientKeyExchange, *KeyBlock, int, []byte, []byte) {
	publicKey := serverHello.Certificate.ServerPublicKey()
	preMastersecret, encryptedPreMastersecret := generatePreMasterSecret(publicKey)

	log.Printf("pre master secret:\n%x\n", preMastersecret)
	log.Printf("encryptedPreMastersecret:\n%x\n", encryptedPreMastersecret)

	encryptedPreMasterLength := &bytes.Buffer{}
	WriteUint16(encryptedPreMasterLength, uint16(len(encryptedPreMastersecret)))

	rsaEncryptedPreMasterSecret := &RSAEncryptedPreMasterSecret{
		EncryptedPreMasterLength: encryptedPreMasterLength.Bytes(),
		EncryptedPreMaster:       encryptedPreMastersecret,
	}

	clientKeyExchange := &ClientKeyExchange{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{TLS_CONTENT_TYPE_HANDSHAKE},
			Version:     TLS_VERSION_1_2,
			Length:      []byte{0x00, 0x00}, // 後で計算するが、初期化のため
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE},
			Length:        uintTo3byte(uint32(len(rsaEncryptedPreMasterSecret.Bytes()))),
		},
		RSAEncryptedPreMasterSecret: rsaEncryptedPreMasterSecret,
	}
	// -5でいいみたい
	tmp := &bytes.Buffer{}
	WriteUint16(tmp, uint16(len(clientKeyExchange.Bytes())-5))
	clientKeyExchange.RecordLayer.Length = tmp.Bytes()

	changeCipherSpecMessage := []byte{0x01}
	tmp = &bytes.Buffer{}
	WriteUint16(tmp, uint16(len(changeCipherSpecMessage)))
	changeCipherSpecProtocol := &ChangeCipherSpecProtocol{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC},
			Version:     TLS_VERSION_1_2,
			Length:      tmp.Bytes(),
		},
		ChangeCipherSpecMessage: changeCipherSpecMessage,
	}

	rawFinished, encrypted, keyblock, clientSequence, master := generateEncryptedHandshakeMessage(preMastersecret, clientHello, serverHello, clientKeyExchange)
	log.Printf("Encrypted:\n%x\n", encrypted)

	return &TLSClientKeyExchange{
		ClientKeyExchange:         clientKeyExchange,
		ChangeCipherSpecProtocol:  changeCipherSpecProtocol,
		EncryptedHandshakeMessage: encrypted,
	}, keyblock, clientSequence, master, rawFinished
}

// ref: https://datatracker.ietf.org/doc/html/rfc5246#section-7.4.7.1
func generatePreMasterSecret(publicKey *rsa.PublicKey) ([]byte, []byte) {
	random := make([]byte, 46)
	// _, err := rand.Read(random)
	// if err != nil {
	// 	log.Println(err)
	// 	return make([]byte, 46+2)
	// }
	clientVersion := TLS_VERSION_1_2

	preMasterSecret := append(clientVersion, random...)
	encryptedPreMasterSecret, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, preMasterSecret)
	if err != nil {
		log.Println(err)
		return nil, nil
	}
	return preMasterSecret, encryptedPreMasterSecret
}

var MasterSecretLable = []byte("master secret")
var KeyLable = []byte("key expansion")

type KeyBlock struct {
	ClientWriteKey []byte
	ServerWriteKey []byte
	ClientWriteIV  []byte
	ServerWriteIV  []byte
}

func generateEncryptedHandshakeMessage(preMasterSecret []byte, clientHello *TLSClientHello, serverHello *TLSServerHello, clientKeyExchange *ClientKeyExchange) ([]byte, []byte, *KeyBlock, int, []byte) {
	var random []byte
	random = append(random, clientHello.HandshakeProtocol.Random...)
	random = append(random, serverHello.ServerHello.HandshakeProtocol.Random...)

	master := prf(preMasterSecret, MasterSecretLable, random, 48)

	var keyrandom []byte
	keyrandom = append(keyrandom, serverHello.ServerHello.HandshakeProtocol.Random...)
	keyrandom = append(keyrandom, clientHello.HandshakeProtocol.Random...)

	keyblockbyte := prf(master, KeyLable, keyrandom, 40)
	keyblock := &KeyBlock{
		ClientWriteKey: keyblockbyte[0:16],
		ServerWriteKey: keyblockbyte[16:32],
		ClientWriteIV:  keyblockbyte[32:36],
		ServerWriteIV:  keyblockbyte[36:40],
	}

	// https://rfcs-web-fc2-com.translate.goog/rfc5246.html?_x_tr_sl=en&_x_tr_tl=ja&_x_tr_hl=ja#page-63
	//   レコードは含めない旨きさいあり
	// https://rfcs-web-fc2-com.translate.goog/rfc5246.html?_x_tr_sl=en&_x_tr_tl=ja&_x_tr_hl=ja#section-7.4
	//   各ハンドシェイクについてきさいあり
	handshakes := []byte{}
	isFromServer := true

	handshakes = append(handshakes, clientHello.HandshakeProtocol.Bytes(!isFromServer)...)
	handshakes = append(handshakes, serverHello.ServerHello.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, serverHello.Certificate.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, serverHello.Certificate.CertificatesLength...)
	handshakes = append(handshakes, serverHello.Certificate.Certificates...)
	handshakes = append(handshakes, serverHello.ServerHelloDone.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, clientKeyExchange.HandshakeProtocol.Bytes(!isFromServer)...)
	handshakes = append(handshakes, clientKeyExchange.RSAEncryptedPreMasterSecret.Bytes()...)
	// ChangeCipherSpecは含まれない記載がrfcにある. ref: https://rfcs-web-fc2-com.translate.goog/rfc5246.html?_x_tr_sl=en&_x_tr_tl=ja&_x_tr_hl=ja#section-7.4 の「7.4.9 . 完了」
	// handshakes = append(handshakes, changeCipherSpecProtocol.ChangeCipherSpecMessage...)

	hasher := sha256.New()
	hasher.Write(handshakes)
	messages := hasher.Sum(nil)
	verifyData := prf(master, []byte("client finished"), messages, 12)

	finMessage := []byte{TLS_HANDSHAKE_TYPE_FINISHED}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)

	encrypted, clientSequenceNum := encryptClientMessage(keyblock, finMessage)
	return finMessage, encrypted, keyblock, clientSequenceNum, master
}

func encryptClientMessage(keyblock *KeyBlock, plaintext []byte) ([]byte, int) {
	length := &bytes.Buffer{}
	WriteUint16(length, uint16(len(plaintext)))

	log.Printf("length.Bytes(): %x\n", length.Bytes())

	h := &TLSRecordLayer{
		ContentType: []byte{TLS_CONTENT_TYPE_HANDSHAKE},
		Version:     TLS_VERSION_1_2,
		Length:      length.Bytes(),
	}
	header := h.Bytes()
	clientSequence := 0
	record_seq := append(header, getNonce(clientSequence, 8)...)

	nonce := keyblock.ClientWriteIV
	nonce = append(nonce, getNonce(clientSequence, 8)...)

	add := getNonce(clientSequence, 8)
	add = append(add, header...)

	block, _ := aes.NewCipher(keyblock.ClientWriteKey)
	aesgcm, _ := cipher.NewGCM(block)

	encryptedMessage := aesgcm.Seal(record_seq, nonce, plaintext, add)
	tmp := &bytes.Buffer{}
	WriteUint16(tmp, uint16(len(encryptedMessage)-5))
	updatelength := tmp.Bytes()
	encryptedMessage[3] = updatelength[0]
	encryptedMessage[4] = updatelength[1]

	return encryptedMessage, clientSequence
}

func getNonce(i, length int) []byte {
	b := make([]byte, length)
	binary.BigEndian.PutUint64(b, uint64(i))
	return b
}

func uintTo3byte(data uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, data)
	return b[1:]
}

// この辺りちょっと拝借させてもらう https://zenn.dev/satoken/articles/golang-tls1_2#%E6%9A%97%E5%8F%B7%E5%8C%96%E3%81%A8finished-message

func prf(secret, label, clientServerRandom []byte, prfLength int) []byte {
	var seed []byte
	seed = append(seed, label...)
	seed = append(seed, clientServerRandom...)
	return phash(secret, seed, prfLength)
}

func phash(secret, seed []byte, prfLength int) []byte {
	result := make([]byte, prfLength)
	mac := hmac.New(sha256.New, secret)
	mac.Write(seed)

	// A(1)
	a := mac.Sum(nil)
	length := 0

	// 必要な長さになるまで計算する
	for length < len(result) {
		mac.Reset()
		mac.Write(a)
		mac.Write(seed)
		b := mac.Sum(nil)
		copy(result[length:], b)
		length += len(b)

		mac.Reset()
		mac.Write(a)
		a = mac.Sum(nil)
	}
	return result
}

type ChangeCipherSpecAndFinished struct {
	ChangeCipherSpecProtocol *ChangeCipherSpecProtocol
	Finished                 *Finished
}

type Finished struct {
	RecordLayer *TLSRecordLayer

	RawEncrypted []byte
}

type ForVerifing struct {
	Master            []byte
	ClientHello       *TLSClientHello
	ServerHello       *TLSServerHello
	ClientKeyExchange *ClientKeyExchange
	ClientFinished    []byte // 暗号化前の
}

// これは、自作 tls handshake 用で、Monitor に表示するためのものではない
func ParsedTLSChangeCipherSpecAndFinished(b []byte, keyblock *KeyBlock, clientSequenceNum int, verifyingData *ForVerifing) *ChangeCipherSpecAndFinished {
	finished := &Finished{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[6]},
			Version:     b[7:9],
			Length:      b[9:11],
		},
		RawEncrypted: b[11:51], // TODO: とりあえずベタで指定
	}

	plaintext := decryptServerMessage(finished, keyblock, clientSequenceNum, TLS_CONTENT_TYPE_HANDSHAKE)
	log.Printf("Finishe.decrypted text:\n%x\n", plaintext)
	if verifyTLSFinished(plaintext, verifyingData) {
		log.Println("Succeeded verify!!")
	} else {
		log.Println("Failed to verify...")
	}

	ret := &ChangeCipherSpecAndFinished{
		ChangeCipherSpecProtocol: &ChangeCipherSpecProtocol{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{b[0]},
				Version:     b[1:3],
				Length:      b[3:5],
			},
			ChangeCipherSpecMessage: []byte{b[5]},
		},

		Finished: finished,
	}
	return ret
}

// ref: https://github.com/sat0ken/go-tcpip/blob/main/tls_prf.go#L173
func decryptServerMessage(finished *Finished, keyblock *KeyBlock, clientSequenceNum int, ctype int) []byte {
	seq_nonce := finished.RawEncrypted[0:8]
	ciphertext := finished.RawEncrypted[8:]

	serverkey := keyblock.ServerWriteKey
	nonce := keyblock.ServerWriteIV
	nonce = append(nonce, seq_nonce...)

	block, _ := aes.NewCipher(serverkey)
	aesgcm, _ := cipher.NewGCM(block)

	var add []byte
	add = getNonce(clientSequenceNum, 8)
	add = append(add, byte(ctype))
	add = append(add, TLS_VERSION_1_2...)
	l := len(ciphertext) - aesgcm.Overhead()
	plainLength := &bytes.Buffer{}
	WriteUint16(plainLength, uint16(l))
	add = append(add, plainLength.Bytes()...)

	log.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		log.Println(err)
		return nil
	}

	return plaintext
}

// encrypt前のclientのfinishedが必要
func verifyTLSFinished(target []byte, v *ForVerifing) bool {
	handshakes := []byte{}
	isFromServer := true

	handshakes = append(handshakes, v.ClientHello.HandshakeProtocol.Bytes(!isFromServer)...)
	handshakes = append(handshakes, v.ServerHello.ServerHello.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, v.ServerHello.Certificate.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, v.ServerHello.Certificate.CertificatesLength...)
	handshakes = append(handshakes, v.ServerHello.Certificate.Certificates...)
	handshakes = append(handshakes, v.ServerHello.ServerHelloDone.HandshakeProtocol.Bytes(isFromServer)...)
	handshakes = append(handshakes, v.ClientKeyExchange.HandshakeProtocol.Bytes(!isFromServer)...)
	handshakes = append(handshakes, v.ClientKeyExchange.RSAEncryptedPreMasterSecret.Bytes()...)
	// ChangeCipherSpecは含まれない記載がrfcにある. ref: https://rfcs-web-fc2-com.translate.goog/rfc5246.html?_x_tr_sl=en&_x_tr_tl=ja&_x_tr_hl=ja#section-7.4 の「7.4.9 . 完了」
	// handshakes = append(handshakes, changeCipherSpecProtocol.ChangeCipherSpecMessage...)
	handshakes = append(handshakes, v.ClientFinished...)

	hasher := sha256.New()
	hasher.Write(handshakes)
	messages := hasher.Sum(nil)

	ret := prf(v.Master, []byte("server finished"), messages, 12)
	log.Printf("target  : %x\n", target)
	log.Printf("verifing: %x\n", ret)

	return bytes.Equal(target[4:], ret)
}

// サーバから来る
type TLSChangeCipherSpecAndEncryptedHandshakeMessage struct {
	ChangeCipherSpecProtocol  *ChangeCipherSpecProtocol
	EncryptedHandshakeMessage *EncryptedHandshakeMessage
}

func (t *TLSChangeCipherSpecAndEncryptedHandshakeMessage) Bytes() []byte {
	buf := bytes.Buffer{}
	buf.Write(t.ChangeCipherSpecProtocol.Bytes())
	buf.Write(t.EncryptedHandshakeMessage.Bytes())
	return buf.Bytes()
}

// これは、Monitor 表示用に、受信したものをただパースする関数
func ParsedTLSChangeCipherSpecAndEncryptedHandshakeMessage(b []byte) *TLSChangeCipherSpecAndEncryptedHandshakeMessage {
	lengthOfChangeCipherSpecProtocol := b[3:5]
	changeCipherSpecProtocol := &ChangeCipherSpecProtocol{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      lengthOfChangeCipherSpecProtocol,
		},
		ChangeCipherSpecMessage: b[5 : 5+bytesToInt(lengthOfChangeCipherSpecProtocol)],
	}
	nextPosition := 5 + bytesToInt(lengthOfChangeCipherSpecProtocol)

	lengthOfEncryptedHandshakeMessage := b[nextPosition+3 : nextPosition+5]
	encryptedHandshakeMessage := &EncryptedHandshakeMessage{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPosition]},
			Version:     b[nextPosition+1 : nextPosition+3],
			Length:      lengthOfEncryptedHandshakeMessage,
		},
	}
	nextPosition += 5
	encryptedHandshakeMessage.EncryptedHandshakeMessage_ = b[nextPosition : nextPosition+bytesToInt(lengthOfEncryptedHandshakeMessage)]

	return &TLSChangeCipherSpecAndEncryptedHandshakeMessage{
		ChangeCipherSpecProtocol:  changeCipherSpecProtocol,
		EncryptedHandshakeMessage: encryptedHandshakeMessage,
	}
}

type TLSApplicationData struct {
	RecordLayer              *TLSRecordLayer
	EncryptedApplicationData []byte
}

func ParsedTLSApplicationData(b []byte) *TLSApplicationData {
	length := b[3:5]
	return &TLSApplicationData{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      length,
		},
		EncryptedApplicationData: b[5 : 5+bytesToInt(length)],
	}
}

func NewTLSApplicationData(data []byte, keyblock *KeyBlock, clientSequence int) []byte {
	encrypted, _ := encryptApplicationData(keyblock, data, clientSequence)
	return encrypted
}

// TODO: encryptClientMessage func と共通化を...
func encryptApplicationData(keyblock *KeyBlock, plaintext []byte, clientSequence int) ([]byte, int) {
	length := &bytes.Buffer{}
	WriteUint16(length, uint16(len(plaintext)))

	log.Printf("length.Bytes(): %x\n", length.Bytes())

	h := &TLSRecordLayer{
		ContentType: []byte{TLS_CONTENT_TYPE_APPLICATION_DATA},
		Version:     TLS_VERSION_1_2,
		Length:      length.Bytes(),
	}
	header := h.Bytes()
	record_seq := append(header, getNonce(clientSequence, 8)...)

	nonce := keyblock.ClientWriteIV
	nonce = append(nonce, getNonce(clientSequence, 8)...)

	add := getNonce(clientSequence, 8)
	add = append(add, header...)

	block, _ := aes.NewCipher(keyblock.ClientWriteKey)
	aesgcm, _ := cipher.NewGCM(block)

	encryptedMessage := aesgcm.Seal(record_seq, nonce, plaintext, add)
	tmp := &bytes.Buffer{}
	WriteUint16(tmp, uint16(len(encryptedMessage)-5))
	updatelength := tmp.Bytes()
	encryptedMessage[3] = updatelength[0]
	encryptedMessage[4] = updatelength[1]

	return encryptedMessage, clientSequence
}

func (a *TLSApplicationData) Bytes() []byte {
	b := []byte{}
	b = append(b, a.RecordLayer.Bytes()...)
	b = append(b, a.EncryptedApplicationData...)
	return b
}

type TLSEncryptedAlert struct {
	RecordLayer  *TLSRecordLayer
	AlertMessage []byte
}

const TLS_CONTENT_TYPE_ALERT = 0x15

func ParsedTLSEncryptedAlert(b []byte) *TLSEncryptedAlert {
	length := b[3:5]
	return &TLSEncryptedAlert{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[0]},
			Version:     b[1:3],
			Length:      length,
		},
		AlertMessage: b[5 : 5+bytesToInt(length)],
	}
}

func (t *TLSEncryptedAlert) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(t.RecordLayer.Bytes())
	buf.Write(t.AlertMessage)
	return buf.Bytes()
}
