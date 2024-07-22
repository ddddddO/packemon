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

const CLIENT_HELLO = 0x01
const COMPRESSION_METHOD_NULL = 0x00

var TLS_VERSION_1_2 = []byte{0x03, 0x03}

func NewTLSClientHello() *TLSClientHello {
	handshake := &TLSHandshakeProtocol{
		HandshakeType: []byte{CLIENT_HELLO},
		Length:        []byte{0x00, 0x00, 0x2b}, // 2b = 43byte
		// Length: []byte{0x00, 0x00, 0x4a}, // 4a = 74byte
		Version:   TLS_VERSION_1_2,
		Random:    make([]byte, 32), // 000000....
		SessionID: []byte{0x00},
		// SessionID: make([]byte, 32),
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
		CompressionMethodsLength: []byte{0x01},
		CompressionMethods:       []byte{COMPRESSION_METHOD_NULL},
		ExtensionsLength:         []byte{0x00, 0x00},
		Extentions:               []byte{},
	}

	lengthHandshake := &bytes.Buffer{}
	isFromServer := false
	WriteUint16(lengthHandshake, uint16(len(handshake.Bytes(isFromServer))))

	return &TLSClientHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{0x16},
			Version:     []byte{0x03, 0x01},
			Length:      lengthHandshake.Bytes(),
		},
		HandshakeProtocol: handshake,
	}
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
	certificateLength := parsedCertificatesLength(b[56:59])
	log.Printf("certificateLength: %d\n", certificateLength)

	return &TLSServerHello{
		ServerHello: &ServerHello{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{b[0]},
				Version:     b[1:3],
				Length:      b[3:5],
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
		},

		Certificate: &Certificate{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{b[47]},
				Version:     b[48:50],
				Length:      b[50:52],
			},
			HandshakeProtocol: &TLSHandshakeProtocol{
				HandshakeType: []byte{b[52]},
				Length:        b[53:56],
			},
			CertificatesLength: b[56:59],
			Certificates:       b[59 : 59+certificateLength],
		},

		ServerHelloDone: &ServerHelloDone{
			RecordLayer: &TLSRecordLayer{
				ContentType: []byte{b[59+certificateLength]},
				Version:     b[59+certificateLength+1 : 59+certificateLength+1+2],
				Length:      b[59+certificateLength+1+2 : 59+certificateLength+1+2+2],
			},
			HandshakeProtocol: &TLSHandshakeProtocol{
				HandshakeType: []byte{b[59+certificateLength+1+2+2]},
				Length:        b[59+certificateLength+1+2+2+1 : 59+certificateLength+1+2+2+1+3],
			},
		},
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
const TLS_HANDSHAKE_TYPE_FINISHED = 0x14
const TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC = 0x14

func NewTLSClientKeyExchange(clientHello *TLSClientHello, serverHello *TLSServerHello) *TLSClientKeyExchange {
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
			ContentType: []byte{0x16},
			Version:     TLS_VERSION_1_2,
			Length:      []byte{0x01, 0x06}, // 262
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE},
			Length:        uintTo3byte(uint32(len(rsaEncryptedPreMasterSecret.Bytes()))),
		},
		RSAEncryptedPreMasterSecret: rsaEncryptedPreMasterSecret,
	}

	changeCipherSpecProtocol := &ChangeCipherSpecProtocol{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC},
			Version:     TLS_VERSION_1_2,
			Length:      []byte{0x00, 0x01},
		},
		ChangeCipherSpecMessage: []byte{0x01},
	}

	encrypted := generateEncryptedHandshakeMessage(preMastersecret, clientHello, serverHello, clientKeyExchange, changeCipherSpecProtocol)
	log.Printf("Encrypted:\n%x\n", encrypted)

	return &TLSClientKeyExchange{
		ClientKeyExchange:         clientKeyExchange,
		ChangeCipherSpecProtocol:  changeCipherSpecProtocol,
		EncryptedHandshakeMessage: encrypted,
	}
}

func lengthEncryptedHandshakeMessage_(b []byte) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(b)))
	return buf
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

func generateEncryptedHandshakeMessage(preMasterSecret []byte, clientHello *TLSClientHello, serverHello *TLSServerHello, clientKeyExchange *ClientKeyExchange, changeCipherSpecProtocol *ChangeCipherSpecProtocol) []byte {
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
	// TODO: ChangeCipherSpecは含まれない記載がrfcにある. ref: https://rfcs-web-fc2-com.translate.goog/rfc5246.html?_x_tr_sl=en&_x_tr_tl=ja&_x_tr_hl=ja#section-7.4 の「7.4.9 . 完了」
	// handshakes = append(handshakes, changeCipherSpecProtocol.ChangeCipherSpecMessage...)

	hasher := sha256.New()
	hasher.Write(handshakes)
	messages := hasher.Sum(nil)
	verifyData := prf(master, []byte("client finished"), messages, 12)

	finMessage := []byte{TLS_HANDSHAKE_TYPE_FINISHED}
	finMessage = append(finMessage, uintTo3byte(uint32(len(verifyData)))...)
	finMessage = append(finMessage, verifyData...)

	encrypted := encryptClientMessage(keyblock, finMessage)
	return encrypted
}

func encryptClientMessage(keyblock *KeyBlock, plaintext []byte) []byte {
	length := &bytes.Buffer{}
	WriteUint16(length, uint16(len(plaintext)))

	log.Printf("length.Bytes(): %x\n", length.Bytes())

	h := &TLSRecordLayer{
		ContentType: []byte{0x16},
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

	return encryptedMessage
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
