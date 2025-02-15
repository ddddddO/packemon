package packemon

import "bytes"

type TLSv12State int

const (
	TLSv12_STATE_INIT TLSv12State = iota
	TLSv12_STATE_PASSIVE_SERVER_HELLO
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
}

func NewTLSv12Connection() *TLSv12Connection {
	return &TLSv12Connection{
		currentState: TLSv12_STATE_INIT,

		TLSClientHello: NewTLSClientHello(),
	}
}

// TODO: ServerHello 以外も拾っちゃってるからちゃんと判定したい
func (t *TLSv12Connection) IsPassiveServerHello(tcp *TCP) bool {
	if t.currentState != TLSv12_STATE_INIT {
		return false
	}

	tlsHandshakeType := []byte{tcp.Data[5]}
	tlsContentType := []byte{tcp.Data[0]}
	return bytes.Equal(tlsHandshakeType, []byte{0x02}) && bytes.Equal(tlsContentType, []byte{TLS_CONTENT_TYPE_HANDSHAKE})
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
