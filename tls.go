package packemon

import (
	"crypto/tls"
	"encoding/binary"
)

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

func (p *TLSHandshakeProtocol) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, p.HandshakeType...)
	buf = append(buf, p.Length...)
	buf = append(buf, p.Version...)
	buf = append(buf, p.Random...)
	buf = append(buf, p.SessionID...)
	buf = append(buf, p.CipherSuitesLength...)
	buf = append(buf, p.bytesCipherSuites()...)
	buf = append(buf, p.CompressionMethodsLength...)
	buf = append(buf, p.CompressionMethods...)
	buf = append(buf, p.ExtensionsLength...)
	buf = append(buf, p.Extentions...)
	return buf
}

func (p *TLSHandshakeProtocol) bytesCipherSuites() []byte {
	buf := []byte{}
	for i := range p.CipherSuites {
		buf = binary.BigEndian.AppendUint16(buf, p.CipherSuites[i])
	}
	return buf
}

// ref: https://tls12.xargs.org/#client-hello/annotated
// 以下のフィールドはWiresharkを見て
type TLSClientHello struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

func NewTLSClientHello() *TLSClientHello {
	const CLIENT_HELLO = 0x01
	const COMPRESSION_METHOD_NULL = 0x00

	return &TLSClientHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{0x16},
			Version:     []byte{0x03, 0x01},
			Length:      []byte{0x00, 0x4d}, // 4d = 77byte len
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType:      []byte{CLIENT_HELLO},
			Length:             []byte{0x00, 0x00, 0x49}, // 49 = 73byte
			Version:            []byte{0x03, 0x03},       // TLS1.2
			Random:             make([]byte, 32),         // 000000....
			SessionID:          []byte{0x00},
			CipherSuitesLength: []byte{0x00, 0x20}, // 32
			// CipherSuites:             []byte{0xcc, 0xa8, 0xcc, 0xa9, 0xc0, 0x2f, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2c, 0xc0, 0x13, 0xc0, 0x09, 0xc0, 0x14, 0xc0, 0x0a, 0x00, 0x9c, 0x00, 0x9d, 0x00, 0x2f, 0x00, 0x35, 0xc0, 0x12, 0x00, 0x0a},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
				tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
			},
			CompressionMethodsLength: []byte{0x01},
			CompressionMethods:       []byte{COMPRESSION_METHOD_NULL},
			ExtensionsLength:         []byte{0x00, 0x00},
			Extentions:               []byte{},
		},
	}
}

func (tch *TLSClientHello) Bytes() []byte {
	buf := []byte{}
	buf = append(buf, tch.RecordLayer.Bytes()...)
	buf = append(buf, tch.HandshakeProtocol.Bytes()...)
	return buf
}
