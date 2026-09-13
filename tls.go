package packemon

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func ParsedTLSToPassive(tcp *TCP, p *Passive) {
	// 以下、tcp.Data[1:3] にある(Record Layer) version あてにならないかも。tls version 1.0 の値でも wireshark 上で、tls1.2 or 1.3 の record という表示になってる
	// なので、HandshakeProtocol 内の、Version でも確認する.
	// が、これもあてにならない。TLS1.3のつもりでリクエストして(curl -s -v --tls-max 1.3 https://192.168.10.112:10443)、Client Hello みると、Version 1.0 / Handshake Protocol Version 1.2
	// if bytes.Equal(TLS_VERSION_1_2, tcp.Data[1:3]) {

	// TODO: support TLSv1.3
	// ref: https://zenn.dev/satoken/articles/golang-tls1_3
	if bytes.Equal(TLS_VERSION_1_0, tcp.Data[1:3]) || // 1.0 / 1.1 とか含めちゃってるのは、そういうのが1.2 / 1.3 でも入ってき得るから
		bytes.Equal(TLS_VERSION_1_1, tcp.Data[1:3]) ||
		bytes.Equal(TLS_VERSION_1_2, tcp.Data[1:3]) ||
		bytes.Equal(TLS_VERSION_1_3, tcp.Data[1:3]) ||
		bytes.Equal(TLS_VERSION_1_2, tcp.Data[9:11]) {

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
				// Server Hello の、Extension.supported_versions に、TLS1.3(0x0304) が含まれていれば、それ用のパースをする
				serverHello, _ := ParsedTLSServerHelloOnly(tcp.Data) // 以下のParsedTLSServerHelloでもこれ呼んでるからなんとかする
				for _, e := range serverHello.HandshakeProtocol.Extentions {
					if e.IsTLS13() {
						tlsServerHelloFor1_3 := ParsedTLSServerHelloFor1_3(tcp.Data)
						p.TLSServerHelloFor1_3 = tlsServerHelloFor1_3
						return
					}
				}

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
	SessionIDLength          []byte
	SessionID                []byte
	CipherSuitesLength       []byte
	CipherSuites             []uint16 // ref: https://tls12.xargs.org/#client-hello/annotated [Ciper Suites]
	CompressionMethodsLength []byte
	CompressionMethods       []byte
	ExtensionsLength         []byte
	Extentions               TLSExtensions
}

var TLS_EXTENSION_TYPE_KEY_SHARE = []byte{0x0, 0x33}

type TLSExtension struct {
	Type   []byte
	Length []byte
	Data   []byte
}

func (e *TLSExtension) Bytes() []byte {
	buf := &bytes.Buffer{}
	buf.Write(e.Type)
	buf.Write(e.Length)
	buf.Write(e.Data)
	return buf.Bytes()
}

var TLS_EXTENSION_SUPPORTED_VERSIONS = []byte{0x00, 0x2b}

func (e *TLSExtension) IsTLS13() bool {
	if !bytes.Equal(e.Type, TLS_EXTENSION_SUPPORTED_VERSIONS) {
		return false
	}

	for i := 0; i < bytesToInt(e.Length); i += 2 {
		supportedVersion := e.Data[i : i+2]
		if bytes.Equal(supportedVersion, TLS_VERSION_1_3) {
			return true
		}
	}
	return false
}

type TLSExtensions []*TLSExtension

func (es TLSExtensions) Bytes() []byte {
	buf := &bytes.Buffer{}
	for _, e := range es {
		buf.Write(e.Bytes())
	}
	return buf.Bytes()
}

func ParsedTLSExtensions(extensionsLength int, b []byte) TLSExtensions {
	if extensionsLength == 0 {
		return TLSExtensions{}
	}

	es := []*TLSExtension{}
	for i := 0; i < extensionsLength; {
		typ := b[i : i+2]
		length := b[i+2 : i+4]
		lengthInt := bytesToInt(length)
		data := b[i+4 : i+4+lengthInt]

		e := &TLSExtension{
			Type:   typ,
			Length: length,
			Data:   data,
		}
		es = append(es, e)

		i = i + 4 + lengthInt
	}

	return es
}

func (p *TLSHandshakeProtocol) Bytes(isFromServer bool) []byte {
	buf := []byte{}
	buf = append(buf, p.HandshakeType...)
	buf = append(buf, p.Length...)
	buf = append(buf, p.Version...)
	buf = append(buf, p.Random...)
	buf = append(buf, p.SessionIDLength...)
	if !(p.SessionIDLength == nil || bytes.Equal(p.SessionIDLength, []byte{0x00})) {
		buf = append(buf, p.SessionID...)
	}
	if clength := p.lengthCipherSuites(isFromServer); clength != nil {
		buf = append(buf, p.lengthCipherSuites(isFromServer)...)
	}
	buf = append(buf, p.bytesCipherSuites()...)
	buf = append(buf, p.CompressionMethodsLength...)
	buf = append(buf, p.CompressionMethods...)
	buf = append(buf, p.ExtensionsLength...)
	buf = append(buf, p.Extentions.Bytes()...)
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

	// TODO: これがこのstruct内にあるのはおかしく、一旦実装を簡単にするため置いてるだけ。要リファクタ
	ECDHEKeys *ECDHEKeys
}

const TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_TYPE_SERVER_HELLO = 0x02
const COMPRESSION_METHOD_NULL = 0x00

var TLS_VERSION_1_0 = []byte{0x03, 0x01}
var TLS_VERSION_1_1 = []byte{0x03, 0x02}
var TLS_VERSION_1_2 = []byte{0x03, 0x03}
var TLS_VERSION_1_3 = []byte{0x03, 0x04}

type ECDHEKeys struct {
	PrivateKey []byte
	PublicKey  []byte
	SharedKey  []byte
}

// TODO: tls1.3 用のと汎用的に
func NewTLSClientHello(tlsVersion []byte, cipherSuites ...uint16) *TLSClientHello {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		panic(err)
	}

	handshake := &TLSHandshakeProtocol{
		HandshakeType: []byte{TLS_HANDSHAKE_TYPE_CLIENT_HELLO},
		Length:        []byte{0x00, 0x00, 0x00}, // 後で計算して求めるが、初期化のため
		Version:       TLS_VERSION_1_2,

		// TODO: debug 環境の https-server あてにリクエストするときは、以下を使う。復号される
		// Random:        make([]byte, 32), // 000000....
		Random: random,

		SessionIDLength: []byte{0x00},
		// SessionID: make([]byte, 32),

		CipherSuitesLength: []byte{0x00, 0x02}, // 一旦固定
		// CipherSuitesLength:       []byte{0x00, 0x04}, // 一旦固定

		CipherSuites:             cipherSuites, // TODO: 外から指定するようにしたので、CipherSuitesLength を計算して求めないといけない
		CompressionMethodsLength: []byte{0x00}, // 後で計算して求めるが、初期化のため
		CompressionMethods:       []byte{COMPRESSION_METHOD_NULL},
		ExtensionsLength:         []byte{0x00, 0x00}, // 後で計算して求めるが、初期化のため
	}

	handshake.CompressionMethodsLength = []byte{byte(len(handshake.CompressionMethods))}
	tmp := &bytes.Buffer{}

	ecdheKeys := &ECDHEKeys{}
	if bytes.Equal(tlsVersion, TLS_VERSION_1_3) {
		// ref: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/tls1_3.go#L16
		clientPrivateKey := make([]byte, 32)
		rand.Read(clientPrivateKey)
		// clientPrivateKey := noRandomByte(32)
		clientPublicKey, err := curve25519.X25519(clientPrivateKey, curve25519.Basepoint)
		if err != nil {
			panic(err)
		}
		ecdheKeys.PrivateKey = clientPrivateKey
		ecdheKeys.PublicKey = clientPublicKey

		handshake.Extentions = []*TLSExtension{
			{
				// supported_groups
				Type:   []byte{0x00, 0x0a},
				Length: []byte{0x00, 0x04},
				Data: []byte{
					/*Supported Groups List Length: 2*/ 0x00, 0x02,
					/*Supported Groups (1 groups): x25519*/ 0x0, 0x1d,
				},
			},
			{
				// ec_point_formats
				Type:   []byte{0x0, 0x0b},
				Length: []byte{0x0, 0x02},
				Data: []byte{
					0x01, 0x00,
				},
			},
			{
				// signature_algorithms
				Type:   []byte{0x0, 0x0d},
				Length: []byte{0x0, 0x1a},
				Data: append(
					[]byte{0x0, 0x18},
					[]byte{
						0x08, 0x04,
						0x04, 0x03, 0x08, 0x07, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x05, 0x03, 0x06, 0x03, 0x02, 0x01, 0x02, 0x03,
					}...,
				),
			},
			{
				// renagotiation_info
				Type:   []byte{0xff, 0x01},
				Length: []byte{0x00, 0x01},
				Data:   []byte{0x00},
			},
			{
				// supported_versions
				Type:   []byte{0x0, 0x2b},
				Length: []byte{0x0, 0x03},
				Data:   append([]byte{0x02}, TLS_VERSION_1_3...),
			},
			{
				// key_share
				Type:   []byte{0x0, 0x33},
				Length: []byte{0x0, 0x26},
				Data: append(
					[]byte{
						/* Client Key Share Length: 36 */ 0x0, 0x24,
						// 以降、Key Share Entry:
						/* Group: x25519 (29) */ 0x0, 0x1d,
						/* Key Exchange Length: 32 */ 0x0, 0x20,
					},
					/* Key Exchange: */ ecdheKeys.PublicKey...),
			},

			// {
			//  // http2 実装するときに使う
			// 	// application_layer_protocol_negotiation
			// },
		}
	}
	WriteUint16(tmp, uint16(len(handshake.Extentions.Bytes())))
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

		ECDHEKeys: ecdheKeys,
	}
}

func ParsedTLSClientHello(b []byte) *TLSClientHello {
	sessionIDLength := b[43]
	sessionIDLengthInt := int(sessionIDLength)

	var sessionID []byte
	nextPoint := 44
	if sessionIDLengthInt > 0 {
		sessionID = b[nextPoint : nextPoint+sessionIDLengthInt]
		nextPoint += sessionIDLengthInt
	}
	cipherSuitesLength := b[nextPoint : nextPoint+2]
	nextPoint += 2
	cipherSuites := []uint16{}

	// たぶん、2byteずつ増えていくでokと思うけど
	sum := 0
	for i := 0; i < (bytesToInt(cipherSuitesLength) / 2); i++ {
		point := i * 2
		cipherSuite := binary.BigEndian.Uint16(b[nextPoint+point : nextPoint+point+2])
		cipherSuites = append(cipherSuites, cipherSuite)
		sum += 2
	}
	nextPoint += sum

	compressionMethodsLength := b[nextPoint]
	compressionMethodsLengthInt := int(compressionMethodsLength)
	compressionMethods := []byte{}
	if compressionMethodsLengthInt > 0 {
		compressionMethods = b[nextPoint+1 : nextPoint+1+compressionMethodsLengthInt]
		nextPoint = nextPoint + 1 + compressionMethodsLengthInt
	}
	extensionsLength := b[nextPoint : nextPoint+2]
	extensionsLengthInt := bytesToInt(extensionsLength)
	nextPoint += 2
	var extensions TLSExtensions
	if extensionsLengthInt > 0 {
		extensions = ParsedTLSExtensions(extensionsLengthInt, b[nextPoint:nextPoint+extensionsLengthInt])
	}

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
			SessionIDLength:          []byte{sessionIDLength},
			SessionID:                sessionID,
			CipherSuitesLength:       cipherSuitesLength,
			CipherSuites:             cipherSuites,
			CompressionMethodsLength: []byte{compressionMethodsLength},
			CompressionMethods:       compressionMethods,
			ExtensionsLength:         extensionsLength,
			Extentions:               extensions,
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
	length, _ := strconv.ParseUint(fmt.Sprintf("%x", c.Certificates[:3]), 16, 16)
	certs, err := x509.ParseCertificates(c.Certificates[3 : 3+length])
	if err != nil {
		return err
	}
	// log.Printf("certificate num: %d\n", len(certs))
	c.certs = certs

	ospool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	// log.Println("start verify server certificate")
	for i := len(c.certs) - 1; i >= 0; i-- {
		opts := x509.VerifyOptions{}
		if len(c.certs[i].DNSNames) == 0 {
			opts.Roots = ospool
		} else {
			opts.Roots = ospool
			opts.DNSName = c.certs[i].DNSNames[0]
			// log.Printf("\tDNS name in server certificate: %s\n", c.certs[i].DNSNames[0])
		}

		if _, err := c.certs[i].Verify(opts); err != nil {
			// TODO: 以下対応までエラーとしないようにする
			// https://github.com/ddddddO/packemon/issues/63

			// log.Printf("\tfailed to verify server certificate: %s\n", err)
			return err
		}
		if i > 0 {
			ospool.AddCert(c.certs[1])
		}
	}
	// log.Println("finish verify server certificate")
	return nil
}

func (c *Certificate) ServerPublicKey() *rsa.PublicKey {
	if len(c.certs) == 0 {
		// log.Println("nil ServerPublicKey")
		return nil
	}
	pub, ok := c.certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		// log.Printf("not public key")
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

// TLS1.2/1.3 共通
func ParsedTLSServerHelloOnly(b []byte) (*ServerHello, int) {
	sessionIDLength := b[43]
	sessionIDLengthInt := int(sessionIDLength)

	nextPosition := 44
	sessionID := []byte{}
	if sessionIDLengthInt != 0 {
		sessionID = b[nextPosition : nextPosition+sessionIDLengthInt]
		nextPosition += sessionIDLengthInt
	}

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
			SessionIDLength:    []byte{sessionIDLength},
			SessionID:          sessionID,
			CipherSuites:       []uint16{parsedCipherSuites(b[nextPosition : nextPosition+2])},
			CompressionMethods: []byte{b[nextPosition+2]},
		},
	}

	nextPosition = nextPosition + 3
	if bytesToInt(slength) > 47 {
		extentionsLength := b[nextPosition : nextPosition+2]
		serverHello.HandshakeProtocol.ExtensionsLength = extentionsLength

		nextPosition += 2
		serverHello.HandshakeProtocol.Extentions = ParsedTLSExtensions(bytesToInt(extentionsLength), b[nextPosition:nextPosition+bytesToInt(extentionsLength)])
		nextPosition += bytesToInt(extentionsLength)
	}

	return serverHello, nextPosition
}

// tls1.2用
func ParsedTLSServerHello(b []byte) *TLSServerHello {
	serverHello, nextPosition := ParsedTLSServerHelloOnly(b)

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

type TLSServerHelloFor1_3 struct {
	ServerHello              *ServerHello
	ChangeCipherSpecProtocol *ChangeCipherSpecProtocol
	ApplicationDataProtocols []*TLSApplicationData
}

func (t *TLSServerHelloFor1_3) Bytes() []byte {
	b := &bytes.Buffer{}
	b.Write(t.ServerHello.Bytes())
	b.Write(t.ChangeCipherSpecProtocol.Bytes())
	for _, app := range t.ApplicationDataProtocols {
		b.Write(app.Bytes())
	}
	return b.Bytes()
}

func (t *TLSServerHelloFor1_3) GetServerKeyShare() []byte {
	for _, extension := range t.ServerHello.HandshakeProtocol.Extentions {
		if bytes.Equal(TLS_EXTENSION_TYPE_KEY_SHARE, extension.Type) {
			return extension.Data[4:]
		}
	}
	return nil
}

// tls1.3用
func ParsedTLSServerHelloFor1_3(b []byte) *TLSServerHelloFor1_3 {
	serverHello, nextPosition := ParsedTLSServerHelloOnly(b)
	b = b[nextPosition:]
	changeCipherSpec, nextPosition := ParsedChangeCipherSpec(b)
	b = b[nextPosition:]

	as := []*TLSApplicationData{}

	// TODO: 多分、パケット2つ結合してからでないとダメかもしれん
	//       ただ、1パケットでも大丈夫なときがありそう
	//       ip header の total length が 1500 超えてるとき、連結するようにすればよさそう(そういうパケットでも、Don't fragment なのはそういうものなの？)
	//       これは確か、Monitor の話
	for {
		applicationData := ParsedTLSApplicationData(b)
		if applicationData == nil || applicationData.RecordLayer.ContentType[0] != TLS_CONTENT_TYPE_APPLICATION_DATA {
			break
		}
		as = append(as, applicationData)
		nextPosition = 5 + bytesToInt(applicationData.RecordLayer.Length)
		b = b[nextPosition:]
	}

	return &TLSServerHelloFor1_3{
		ServerHello:              serverHello,
		ChangeCipherSpecProtocol: changeCipherSpec,
		ApplicationDataProtocols: as,
	}
}

// こちらも拝借させてもらってる
// ref: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/tls1_3.go#L88
func DecryptChacha20(header []byte, chipertext []byte, tlsConn *TLSv12Connection) []byte {
	// header := message[0:5]
	// chipertext := message[5:]
	// chipertext := message
	var key, iv, nonce []byte

	if tlsConn.currentHandshake {
		key = tlsConn.KeyBlockForTLSv13.serverHandshakeKey
		iv = tlsConn.KeyBlockForTLSv13.serverHandshakeIV
		nonce = getNonce(tlsConn.ServerHandshakeSeq, 8)
	} else {
		key = tlsConn.KeyBlockForTLSv13.serverAppKey
		iv = tlsConn.KeyBlockForTLSv13.serverAppIV
		nonce = getNonce(tlsConn.ServerAppSeq, 8)
	}

	//fmt.Printf("key is %x, iv is %x\n", key, iv)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		panic(err)
	}

	xornonce := getXORNonce(nonce, iv)

	//fmt.Printf("decrypt nonce is %x xornonce is %x, chipertext is %x, add is %x\n", nonce, xornonce, chipertext, header)
	plaintext, err := aead.Open(nil, xornonce, chipertext, header)
	if err != nil {
		panic(err)
	}
	// fmt.Printf("plaintext is : %x\n", plaintext)
	return plaintext
}

func EncryptChacha20(message []byte, tlsConn *TLSv12Connection) []byte {
	var key, iv, nonce []byte

	// Finishedメッセージを送るとき
	if tlsConn.currentHandshake {
		key = tlsConn.KeyBlockForTLSv13.clientHandshakeKey
		iv = tlsConn.KeyBlockForTLSv13.clientHandshakeIV
		nonce = getNonce(tlsConn.ClientHandshakeSeq, 8)
	} else {
		// Application Dataを送る時
		key = tlsConn.KeyBlockForTLSv13.clientAppKey
		iv = tlsConn.KeyBlockForTLSv13.clientAppIV
		nonce = getNonce(tlsConn.ClientAppSeq, 8)
	}

	// fmt.Printf("key is %x, iv is %x\n", key, iv)

	aead, err := chacha20poly1305.New(key)
	if err != nil {
		log.Fatal(err)
	}
	// ivとnonceをxorのbit演算をする
	// 5.3. レコードごとのノンス
	// 2.埋め込まれたシーケンス番号は、静的なclient_write_ivまたはserver_write_iv（役割に応じて）とXORされます。
	xornonce := getXORNonce(nonce, iv)
	header := strtoByte("170303")
	// 平文→暗号化したときのOverHeadを足す
	totalLength := len(message) + 16

	b := &bytes.Buffer{}
	WriteUint16(b, uint16(totalLength))
	header = append(header, b.Bytes()...)

	// fmt.Printf("encrypt now nonce is %x xornonce is %x, plaintext is %x, add is %x\n", nonce, xornonce, message, header)
	ciphertext := aead.Seal(header, xornonce, message, header)

	return ciphertext
}

type CertificateVerify struct {
	HandshakeType           byte
	Length                  []byte
	SignatureHashAlgorithms []byte
	SignatureLength         []byte
	Signature               []byte
}

const str0x20x64 = "20202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020"

var serverCertificateContextString = []byte(`TLS 1.3, server CertificateVerify`)

// ref: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/tls1_3.go#L285
func (c *CertificateVerify) VerifyServerCertificate(pubkey *rsa.PublicKey, handshake_messages []byte) error {
	hash_messages := WriteHash(handshake_messages)

	hasher := sha256.New()
	// 64回繰り返されるオクテット32（0x20）で構成される文字列
	hasher.Write(strtoByte(str0x20x64))
	// コンテキスト文字列 = "TLS 1.3, server CertificateVerify"
	hasher.Write(serverCertificateContextString)
	// セパレータとして機能する単一の0バイト
	hasher.Write([]byte{0x00})
	hasher.Write(hash_messages)
	signed := hasher.Sum(nil)
	// fmt.Printf("hash_messages is %x\n, signed is %x\n", hash_messages, signed)

	signOpts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
	if err := rsa.VerifyPSS(pubkey, crypto.SHA256, signed, c.Signature, signOpts); err != nil {
		return err
	}
	return nil
}

type FinishedMessage struct {
	HandshakeType byte
	Length        []byte
	VerifyData    []byte
}

func (f *FinishedMessage) Bytes() []byte {
	b := &bytes.Buffer{}
	b.WriteByte(f.HandshakeType)
	b.Write(f.Length)
	b.Write(f.VerifyData)
	return b.Bytes()
}

// TLS1.3用
// https://tex2e.github.io/rfc-translater/html/rfc8446.html
// シーケンス番号とwrite_ivをxorした値がnonceになる
func getXORNonce(seqnum, writeiv []byte) []byte {
	nonce := make([]byte, len(writeiv))
	copy(nonce, writeiv)

	for i, b := range seqnum {
		nonce[4+i] ^= b
	}
	return nonce
}

func strtoByte(str string) []byte {
	b, _ := hex.DecodeString(str)
	return b
}

func parsedCipherSuites(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
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

	// log.Printf("pre master secret:\n%x\n", preMastersecret)
	// log.Printf("encryptedPreMastersecret:\n%x\n", encryptedPreMastersecret)

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
	// log.Printf("Encrypted:\n%x\n", encrypted)

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
		// log.Println(err)
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

	// log.Printf("length.Bytes(): %x\n", length.Bytes())

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

// TODO: 上の encryptClientMessage と共通化を
func EncryptClientMessageForAlert(keyblock *KeyBlock, clientSequence int, plaintext []byte) ([]byte, int) {
	length := &bytes.Buffer{}
	WriteUint16(length, uint16(len(plaintext)))

	// log.Printf("length.Bytes(): %x\n", length.Bytes())

	h := &TLSRecordLayer{
		ContentType: []byte{TLS_CONTENT_TYPE_ALERT},
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
	lengthOfChangeCipherSpecProtocol := b[3:5]
	ret := &ChangeCipherSpecAndFinished{
		ChangeCipherSpecProtocol: &ChangeCipherSpecProtocol{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{b[0]},
				Version:     b[1:3],
				Length:      lengthOfChangeCipherSpecProtocol,
			},
			ChangeCipherSpecMessage: b[5 : 5+bytesToInt(lengthOfChangeCipherSpecProtocol)],
		},
	}
	nextPoint := 5 + bytesToInt(lengthOfChangeCipherSpecProtocol)

	lengthOfFinished := b[nextPoint+3 : nextPoint+5]
	finished := &Finished{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{b[nextPoint]},
			Version:     b[nextPoint+1 : nextPoint+3],
			Length:      lengthOfFinished,
		},
		RawEncrypted: b[nextPoint+5 : nextPoint+5+bytesToInt(lengthOfFinished)],
	}
	ret.Finished = finished

	plaintext := decryptServerMessage(finished, keyblock, clientSequenceNum, TLS_CONTENT_TYPE_HANDSHAKE)
	// log.Printf("Finishe.decrypted text:\n%x\n", plaintext)
	if verifyTLSFinished(plaintext, verifyingData) {
		// log.Println("Succeeded verify!!")
	} else {
		// log.Println("Failed to verify...")
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

	// log.Printf("nonce is : %x, ciphertext is %x, add is %x\n", nonce, ciphertext, add)
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, add)
	if err != nil {
		// log.Println(err)
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
	// log.Printf("👺target  : %x\n", target)
	// log.Printf("👺verifing: %x\n", ret)
	if len(target) > 4 {
		return bytes.Equal(target[4:], ret)
	}
	return false // FIXME:
}

// サーバから来る
type TLSChangeCipherSpecAndEncryptedHandshakeMessage struct {
	ChangeCipherSpecProtocol  *ChangeCipherSpecProtocol
	EncryptedHandshakeMessage *EncryptedHandshakeMessage
}

func (t *TLSChangeCipherSpecAndEncryptedHandshakeMessage) Bytes() []byte {
	buf := bytes.Buffer{}
	buf.Write(t.ChangeCipherSpecProtocol.Bytes())
	if t.EncryptedHandshakeMessage != nil {
		buf.Write(t.EncryptedHandshakeMessage.Bytes())
	}
	return buf.Bytes()
}

// これは、Monitor 表示用に、受信したものをただパースする関数
func ParsedTLSChangeCipherSpecAndEncryptedHandshakeMessage(b []byte) *TLSChangeCipherSpecAndEncryptedHandshakeMessage {
	changeCipherSpecProtocol, nextPosition := ParsedChangeCipherSpec(b)

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

func ParsedChangeCipherSpec(b []byte) (*ChangeCipherSpecProtocol, int) {
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

	return changeCipherSpecProtocol, nextPosition
}

type TLSApplicationData struct {
	RecordLayer              *TLSRecordLayer
	EncryptedApplicationData []byte
}

func ParsedTLSApplicationData(b []byte) *TLSApplicationData {
	length := b[3:5]

	if len(b) < bytesToInt(length)+5 {
		return nil
	}

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

	// log.Printf("length.Bytes(): %x\n", length.Bytes())

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

func DecryptApplicationData(encryptedText []byte, keyBlock *KeyBlock, clientSequence int) []byte {
	f := &Finished{
		RawEncrypted: encryptedText,
	}
	return decryptServerMessage(f, keyBlock, clientSequence, TLS_CONTENT_TYPE_APPLICATION_DATA)
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

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (rl *TLSRecordLayer) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "Record Layer",
		Children: []*FieldNode{
			{Name: "Content Type", Value: fmt.Sprintf("%#x", rl.ContentType)},
			{Name: "Version", Value: fmt.Sprintf("%#x", rl.Version)},
			{Name: "Length", Value: fmt.Sprintf("%#x", rl.Length)},
		},
	}
}

// tlsHandshakeProtocolFieldNode は Client Hello / Server Hello 共通の Handshake Protocol ノードを組み立てる。
// isFromServer が true のときは Cipher Suite / Compression Method を単数表記にする（既存の表示に合わせる）。
func tlsHandshakeProtocolFieldNode(name string, hp *TLSHandshakeProtocol, isFromServer bool) *FieldNode {
	node := &FieldNode{
		Name: name,
		Children: []*FieldNode{
			{Name: "Handshake Type", Value: fmt.Sprintf("%#x", hp.HandshakeType)},
			{Name: "Length", Value: fmt.Sprintf("%#x", hp.Length)},
			{Name: "Version", Value: fmt.Sprintf("%#x", hp.Version)},
			{Name: "Random", Value: fmt.Sprintf("%#x", hp.Random)},
			{Name: "Session ID Length", Value: fmt.Sprintf("%#x", hp.SessionIDLength)},
			{Name: "Session ID", Value: fmt.Sprintf("%#x", hp.SessionID)},
		},
	}
	if isFromServer {
		node.Children = append(node.Children,
			&FieldNode{Name: "Cipher Suite", Value: fmt.Sprintf("%#x", hp.CipherSuites)},
			&FieldNode{Name: "Compression Method", Value: fmt.Sprintf("%#x", hp.CompressionMethods)},
		)
	} else {
		node.Children = append(node.Children,
			&FieldNode{Name: "Cipher Suites Length", Value: fmt.Sprintf("%#x", hp.CipherSuitesLength)},
			&FieldNode{Name: "Cipher Suites", Value: fmt.Sprintf("%#x", hp.CipherSuites)},
			&FieldNode{Name: "Compression Methods Length", Value: fmt.Sprintf("%#x", hp.CompressionMethodsLength)},
			&FieldNode{Name: "Compression Methods", Value: fmt.Sprintf("%#x", hp.CompressionMethods)},
		)
	}
	if hp.ExtensionsLength != nil {
		node.Children = append(node.Children,
			&FieldNode{Name: "Extensions Length", Value: fmt.Sprintf("%#x", hp.ExtensionsLength)})
	}
	for i, e := range hp.Extentions {
		node.Children = append(node.Children, &FieldNode{
			Name: fmt.Sprintf("Extension %d", i),
			Children: []*FieldNode{
				{Name: "Type", Value: fmt.Sprintf("%#x", e.Type)},
				{Name: "Length", Value: fmt.Sprintf("%#x", e.Length)},
				{Name: "Data", Value: fmt.Sprintf("%#x", e.Data)},
			},
		})
	}
	return node
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSClientHello) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Client Hello",
		Children: []*FieldNode{
			t.RecordLayer.FieldNode(),
			tlsHandshakeProtocolFieldNode("Handshake Protocol - Client Hello", t.HandshakeProtocol, false),
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
// TODO: Certificate / ServerHelloDone の表示（既存の表示も ServerHello のみだった）
func (t *TLSServerHello) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Server Hello",
		Children: []*FieldNode{
			t.ServerHello.RecordLayer.FieldNode(),
			tlsHandshakeProtocolFieldNode("Handshake Protocol - Server Hello", t.ServerHello.HandshakeProtocol, true),
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSServerHelloFor1_3) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Server Hello (TLSv1.3)",
		Children: []*FieldNode{
			t.ServerHello.RecordLayer.FieldNode(),
			tlsHandshakeProtocolFieldNode("Handshake Protocol - Server Hello", t.ServerHello.HandshakeProtocol, true),
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSClientKeyExchange) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Client Key Exchange",
		Children: []*FieldNode{
			{Name: "Client Key Exchange", Value: fmt.Sprintf("%#x", t.ClientKeyExchange.Bytes())},
			{Name: "Change Cipher Spec Protocol", Value: fmt.Sprintf("%#x", t.ChangeCipherSpecProtocol.Bytes())},
			{Name: "Encrypted Handshake Message", Value: fmt.Sprintf("%#x", t.EncryptedHandshakeMessage)},
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSChangeCipherSpecAndEncryptedHandshakeMessage) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Change Cipher Spec & Encrypted Handshake Message",
		Children: []*FieldNode{
			{Name: "Change Cipher Spec Protocol", Value: fmt.Sprintf("%#x", t.ChangeCipherSpecProtocol.Bytes())},
			{Name: "Encrypted Handshake Message", Value: fmt.Sprintf("%#x", t.EncryptedHandshakeMessage.Bytes())},
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSApplicationData) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Application Data",
		Children: []*FieldNode{
			t.RecordLayer.FieldNode(),
			{Name: "Encrypted Application Data", Value: fmt.Sprintf("%#x", t.EncryptedApplicationData)},
		},
	}
}

// FieldNode は、Monitor 詳細表示（Dissector バックエンド）向けのフィールドツリーを返す。
func (t *TLSEncryptedAlert) FieldNode() *FieldNode {
	return &FieldNode{
		Name: "TLS Encrypted Alert",
		Children: []*FieldNode{
			t.RecordLayer.FieldNode(),
			{Name: "Alert Message", Value: fmt.Sprintf("%#x", t.AlertMessage)},
		},
	}
}
