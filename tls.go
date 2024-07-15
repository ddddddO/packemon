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
		RecordHeader:      []byte{0x16, 0x03, 0x03, 0x00, 0x4d}, // 4d = 77byte len
		HandshakeHeader:   []byte{CLIENT_HELLO, 0x00, 0x00, 0xa1},
		ClientVersion:     []byte{0x03, 0x03},
		ClientRandom:      make([]byte, 32),
		SessionID:         []byte{0x00},
		CipherSuites:      []byte{0x00, 0x20, 0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a},
		CompressionMethod: []byte{0x01, 0x00},
		ExtensionsLength:  []byte{0x00, 0x00},
	}
}

func (tch *TLSClientHello) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, tch.RecordHeader...)
	buf = append(buf, tch.HandshakeHeader...)
	buf = append(buf, tch.ClientVersion...)
	buf = append(buf, tch.ClientRandom...)
	buf = append(buf, tch.SessionID...)
	buf = append(buf, tch.CipherSuites...)
	buf = append(buf, tch.CompressionMethod...)
	buf = append(buf, tch.ExtensionsLength...)
	buf = append(buf, tch.Extentions...)
	return buf
}
