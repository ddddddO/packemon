package packemon

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"

	"golang.org/x/crypto/hkdf"
)

type TLSv12State int

const (
	TLSv12_STATE_INIT TLSv12State = iota
	TLSv12_STATE_PASSIVE_SERVER_HELLO
	TLSv12_STATE_SEND_APPLICATION_DATA
)

type TLSv12Connection struct {
	currentState TLSv12State
	established  bool

	TLSClientHello       *TLSClientHello
	TLSServerHello       *TLSServerHello
	TLSClientKeyExchange *TLSClientKeyExchange
	TLSClientFinished    []byte
	KeyBlock             *KeyBlock
	ClientSequence       int
	Master               []byte

	// 以降、tlsv1.3実装で追加したものたち
	ECDHEKeys            *ECDHEKeys
	KeyBlockForTLSv13    *KeyBlockForTLSv13
	TLSServerHelloFor1_3 *TLSServerHelloFor1_3
	currentHandshake     bool
	handshakeMessages    []byte
	ServerHandshakeSeq   int
	ServerAppSeq         int
	ClientHandshakeSeq   int
	ClientAppSeq         int
}

func NewTLSv12Connection() *TLSv12Connection {
	return &TLSv12Connection{
		currentState: TLSv12_STATE_INIT,

		TLSClientHello: NewTLSClientHello(TLS_VERSION_1_2, tls.TLS_RSA_WITH_AES_128_GCM_SHA256),
	}
}

// TODO: 1.3用のstructを？
func NewTLSv13Connection() *TLSv12Connection {
	clientHello := NewTLSClientHello(TLS_VERSION_1_3, tls.TLS_CHACHA20_POLY1305_SHA256)

	return &TLSv12Connection{
		currentState:      TLSv12_STATE_INIT,
		handshakeMessages: clientHello.HandshakeProtocol.Bytes(false), // シーケンスが進むにつれappendされてく

		TLSClientHello: clientHello,
		ECDHEKeys:      clientHello.ECDHEKeys,
	}
}

type KeyBlockForTLSv13 struct {
	handshakeSecret       []byte
	clientHandshakeSecret []byte
	clientHandshakeKey    []byte
	clientHandshakeIV     []byte
	ClientFinishedKey     []byte
	serverHandshakeSecret []byte
	serverHandshakeKey    []byte
	serverHandshakeIV     []byte
	ServerFinishedKey     []byte
	masterSecret          []byte
	clientAppSecret       []byte
	clientAppKey          []byte
	clientAppIV           []byte
	serverAppSecret       []byte
	serverAppKey          []byte
	serverAppIV           []byte
}

var TLSv13_DerivedLabel = []byte(`derived`)
var TLSv13_ClienthsTraffic = []byte(`c hs traffic`)
var TLSv13_ClientapTraffic = []byte(`c ap traffic`)
var TLSv13_ServerhsTraffic = []byte(`s hs traffic`)
var TLSv13_ServerapTraffic = []byte(`s ap traffic`)
var TLSv13_FinishedLabel = []byte(`finished`)

// 丸っと拝借させて頂いた
// コード: https://github.com/sat0ken/go-tcpip/blob/7dd5085f8aa25747a6098cc7d8d8e336ec5fcadd/tls1_3.go#L192
// 記事：https://zenn.dev/satoken/articles/golang-tls1_3#tls1.3%E3%81%AE%E9%8D%B5%E7%94%9F%E6%88%90%E3%81%AE%E6%B5%81%E3%82%8C
// TODO: やっぱりレシーバがTLSv1.2用のはおかしいから、v1.3用の作るか、共用に命名変更するかする
func (t *TLSv12Connection) KeyscheduleToMasterSecret(sharedkey []byte) {
	hkdfExtract := func(secret, salt []byte) []byte {
		hash := sha256.New
		return hkdf.Extract(hash, secret, salt)
	}

	zero := noRandomByte(32)
	zerohash := WriteHash(nil)
	// 0からearly secretを作成する
	earlySecret := hkdfExtract(zero, zero)

	// {client} derive secret for handshake "tls13 derived"
	derivedSecretForhs := deriveSecret(earlySecret, TLSv13_DerivedLabel, zerohash)
	// fmt.Printf("derivedSecretForhs %x\n", derivedSecretForhs)

	// {client} extract secret "handshake":
	handshake_secret := hkdfExtract(sharedkey, derivedSecretForhs)
	// fmt.Printf("handshake_secret is : %x\n", handshake_secret)

	hash_messages := WriteHash(t.handshakeMessages) // client hello + server hello
	// fmt.Printf("hashed messages is %x\n", hash_messages)

	// {client} derive secret "tls13 c hs traffic":
	chstraffic := deriveSecret(handshake_secret, TLSv13_ClienthsTraffic, hash_messages)
	// fmt.Printf("CLIENT_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, chstraffic)

	// Finished message用のキー
	clientfinkey := deriveSecret(chstraffic, TLSv13_FinishedLabel, nil)
	//fmt.Printf("clientfinkey is : %x\n", clientfinkey)

	// {client} derive secret "tls13 s hs traffic":
	shstraffic := deriveSecret(handshake_secret, TLSv13_ServerhsTraffic, hash_messages)
	// fmt.Printf("SERVER_HANDSHAKE_TRAFFIC_SECRET %x %x\n", zero, shstraffic)

	// Finished message用のキー
	serverfinkey := deriveSecret(shstraffic, TLSv13_FinishedLabel, nil)
	// fmt.Printf("serverfinkey is : %x\n", serverfinkey)

	derivedSecretFormaster := deriveSecret(handshake_secret, TLSv13_DerivedLabel, zerohash)
	// fmt.Printf("derivedSecretFormaster is : %x\n", derivedSecretFormaster)

	extractSecretMaster := hkdfExtract(zero, derivedSecretFormaster)
	// fmt.Printf("extractSecretMaster is : %x\n", extractSecretMaster)

	// {client} derive write traffic keys for handshake data from server hs traffic:
	// 7.3. トラフィックキーの計算
	clienttraffickey := hkdfExpandLabel(chstraffic, []byte(`key`), nil, 32)
	// fmt.Printf("client traffic key is : %x\n", clienttraffickey)

	clienttrafficiv := hkdfExpandLabel(chstraffic, []byte(`iv`), nil, 12)
	// fmt.Printf("client traffic iv is : %x\n", clienttrafficiv)

	servertraffickey := hkdfExpandLabel(shstraffic, []byte(`key`), nil, 32)
	// fmt.Printf("server traffic key is : %x\n", servertraffickey)

	servertrafficiv := hkdfExpandLabel(shstraffic, []byte(`iv`), nil, 12)
	// fmt.Printf("server traffic iv is : %x\n", servertrafficiv)

	t.KeyBlockForTLSv13 = &KeyBlockForTLSv13{
		handshakeSecret:       handshake_secret,
		clientHandshakeSecret: chstraffic,
		clientHandshakeKey:    clienttraffickey,
		clientHandshakeIV:     clienttrafficiv,
		ClientFinishedKey:     clientfinkey,
		serverHandshakeSecret: shstraffic,
		serverHandshakeKey:    servertraffickey,
		serverHandshakeIV:     servertrafficiv,
		ServerFinishedKey:     serverfinkey,
		masterSecret:          extractSecretMaster,
	}
}

// こちらも
func (t *TLSv12Connection) KeyscheduleToAppTraffic() {
	hash_messages := WriteHash(t.handshakeMessages)
	// fmt.Printf("hashed messages is %x\n", hash_messages)

	// zero := noRandomByte(32)

	// {client} derive secret "tls13 c ap traffic":
	captraffic := deriveSecret(t.KeyBlockForTLSv13.masterSecret, TLSv13_ClientapTraffic, hash_messages)
	// fmt.Printf("CLIENT_TRAFFIC_SECRET_0 %x %x\n", zero, captraffic)
	saptraffic := deriveSecret(t.KeyBlockForTLSv13.masterSecret, TLSv13_ServerapTraffic, hash_messages)
	// fmt.Printf("SERVER_TRAFFIC_SECRET_0 %x %x\n", zero, saptraffic)

	// 7.3. トラフィックキーの計算, Application用
	t.KeyBlockForTLSv13.clientAppKey = hkdfExpandLabel(captraffic, []byte(`key`), nil, 32)
	t.KeyBlockForTLSv13.clientAppIV = hkdfExpandLabel(captraffic, []byte(`iv`), nil, 12)
	// fmt.Printf("clientAppKey and IV is : %x, %x\n", t.KeyBlockForTLSv13.clientAppKey, t.KeyBlockForTLSv13.clientAppIV)

	t.KeyBlockForTLSv13.serverAppKey = hkdfExpandLabel(saptraffic, []byte(`key`), nil, 32)
	t.KeyBlockForTLSv13.serverAppIV = hkdfExpandLabel(saptraffic, []byte(`iv`), nil, 12)
	// fmt.Printf("serverAppkey and IV is : %x, %x\n", t.KeyBlockForTLSv13.serverAppKey, t.KeyBlockForTLSv13.serverAppIV)
}

func hkdfExpand(secret, hkdflabel []byte, length int) []byte {
	hash := sha256.New
	expand := hkdf.Expand(hash, secret, hkdflabel)
	b := make([]byte, length)
	io.ReadFull(expand, b)

	return b
}

func hkdfExpandLabel(secret, label, ctx []byte, length int) []byte {
	// labelを作成
	tlslabel := []byte(`tls13 `)
	tlslabel = append(tlslabel, label...)

	// lengthをセット
	hkdflabel := UintTo2byte(uint16(length))
	hkdflabel = append(hkdflabel, byte(len(tlslabel)))
	hkdflabel = append(hkdflabel, tlslabel...)

	hkdflabel = append(hkdflabel, byte(len(ctx)))
	hkdflabel = append(hkdflabel, ctx...)

	return hkdfExpand(secret, hkdflabel, length)
}

func deriveSecret(secret, label, messages_byte []byte) []byte {
	return hkdfExpandLabel(secret, label, messages_byte, 32)
}

func UintTo2byte(data uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, data)
	return b
}

// TODO: ServerHello 以外も拾っちゃってるからちゃんと判定したい
func (t *TLSv12Connection) IsPassiveServerHello(tcp *TCP) bool {
	if t.currentState != TLSv12_STATE_INIT {
		return false
	}

	tlsHandshakeType := []byte{tcp.Data[5]}
	tlsContentType := []byte{tcp.Data[0]}
	ret := bytes.Equal(tlsHandshakeType, []byte{0x02}) && bytes.Equal(tlsContentType, []byte{TLS_CONTENT_TYPE_HANDSHAKE})
	if ret {
		t.currentState = TLSv12_STATE_PASSIVE_SERVER_HELLO
	}
	return t.currentState == TLSv12_STATE_PASSIVE_SERVER_HELLO
}

func (t *TLSv12Connection) IsPassiveChangeCipherSpecAndFinished(tcp *TCP) bool {
	tlsContentType := []byte{tcp.Data[0]}
	return bytes.Equal(tlsContentType, []byte{TLS_CONTENT_TYPE_CHANGE_CIPHER_SPEC})
}

func (t *TLSv12Connection) VerifingData() *ForVerifing {
	return &ForVerifing{
		Master:            t.Master,
		ClientHello:       t.TLSClientHello,
		ServerHello:       t.TLSServerHello,
		ClientKeyExchange: t.TLSClientKeyExchange.ClientKeyExchange,
		ClientFinished:    t.TLSClientFinished,
	}
}

func (t *TLSv12Connection) SetState(s TLSv12State) {
	t.currentState = s
}

func (t *TLSv12Connection) EstablishedConnection() {
	t.established = true
}

func (t *TLSv12Connection) IsEstablished() bool {
	return t.established
}

func (t *TLSv12Connection) IsSendApplicationData() bool {
	return t.currentState == TLSv12_STATE_SEND_APPLICATION_DATA
}

func (t *TLSv12Connection) Close() {
	t.established = false
}
