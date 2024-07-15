package packemon

// https://tls12.xargs.org/#client-hello/annotated
type TLSClientHello struct {
	RecordHeader      []byte
	HandshakeHeader   []byte
	ClientVersion     []byte
	ClientRandom      []byte
	SessionID         []byte
	CipherSuites      []byte
	CompressionMethod []byte
	ExtensionsLength  []byte
	Extentions        []byte // サイト見ると結構種類有りそう
}

func NewTLSClientHello() *TLSClientHello {
	const CLIENT_HELLO = 0x01

	return &TLSClientHello{
		// 03 03 = TLS1.2
		RecordHeader:    []byte{0x16, 0x03, 0x03, 0x00, 0xa5},
		HandshakeHeader: []byte{CLIENT_HELLO, 0x00, 0x00, 0xa1},
		ClientVersion:   []byte{0x03, 0x03},
		// TODO: 以降
	}
}

func (tch *TLSClientHello) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, tch.RecordHeader...)
	buf = append(buf, tch.HandshakeHeader...)
	buf = append(buf, tch.ClientVersion...)
	return buf
}
