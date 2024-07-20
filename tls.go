package packemon

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"log"
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
	// buf = append(buf, p.CipherSuitesLength...)
	buf = append(buf, p.lengthCipherSuites()...)
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

func (p *TLSHandshakeProtocol) lengthCipherSuites() []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, uint16(len(p.CipherSuites)*2)) // 2byteなため×2
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
	var TLS_VERSION_1_2 = []byte{0x03, 0x03}

	return &TLSClientHello{
		RecordLayer: &TLSRecordLayer{
			ContentType: []byte{0x16},
			Version:     []byte{0x03, 0x01},
			Length:      []byte{0x00, 0x4d}, // 4d = 77byte len
		},
		HandshakeProtocol: &TLSHandshakeProtocol{
			HandshakeType: []byte{CLIENT_HELLO},
			Length:        []byte{0x00, 0x00, 0x49}, // 49 = 73byte
			Version:       TLS_VERSION_1_2,
			Random:        make([]byte, 32), // 000000....
			SessionID:     []byte{0x00},
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

type TLSServerHello struct {
	ServerHello     *ServerHello
	Certificate     *Certificate
	ServerHelloDone *ServerHelloDone
}

type ServerHello struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

type Certificate struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

type ServerHelloDone struct {
	RecordLayer       *TLSRecordLayer
	HandshakeProtocol *TLSHandshakeProtocol
}

func ParsedTLSServerHello(b []byte) *TLSServerHello {
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
	}
}

func parsedCipherSuites(b []byte) uint16 {
	if bytes.Equal(b, []byte{0x00, 0x9c}) {
		return tls.TLS_RSA_WITH_AES_128_GCM_SHA256
	}

	log.Printf("TLS not parsed CipherSuites: %x\n", b)
	return tls.TLS_RSA_WITH_AES_128_GCM_SHA256
}
