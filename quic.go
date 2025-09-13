package packemon

import (
	"crypto/tls"

	"github.com/quic-go/quic-go"
)

type QUIC struct {
	TLSConfig *tls.Config
	Config    *quic.Config
}
