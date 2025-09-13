package packemon

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	"net/url"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

type udpAddrs struct {
	local  *net.UDPAddr
	remote *net.UDPAddr
}

func SendUDP_QUIC_HTTP_Payload(ctx context.Context, fIpv4 *IPv4, fUdp *UDP, fQuic *QUIC, fHttp *HTTP) error {
	localIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(localIPBytes, fIpv4.SrcAddr)
	localUDPAddr, err := createUDPAddr(localIPBytes, fUdp.SrcPort)
	if err != nil {
		return err
	}

	remoteIPBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteIPBytes, fIpv4.DstAddr)
	remoteUDPAddr, err := createUDPAddr(remoteIPBytes, fUdp.DstPort)
	if err != nil {
		return err
	}

	return sendUDP_QUIC_HTTP_Payload(ctx, &udpAddrs{local: localUDPAddr, remote: remoteUDPAddr}, fQuic, fHttp)
}

func SendUDP_QUIC_HTTP_PayloadForIPv6(ctx context.Context, fIpv6 *IPv6, fUdp *UDP, fQuic *QUIC, fHttp *HTTP) error {
	localUDPAddr, err := createUDPAddr(fIpv6.SrcAddr, fUdp.SrcPort)
	if err != nil {
		return err
	}

	remoteUDPAddr, err := createUDPAddr(fIpv6.DstAddr, fUdp.DstPort)
	if err != nil {
		return err
	}

	return sendUDP_QUIC_HTTP_Payload(ctx, &udpAddrs{local: localUDPAddr, remote: remoteUDPAddr}, fQuic, fHttp)
}

func sendUDP_QUIC_HTTP_Payload(ctx context.Context, udpAddrs *udpAddrs, fQuic *QUIC, fHttp *HTTP) error {
	network := "udp"

	// リモート指定はダメみたい. なので代わりに net.ListenUDP を使えと. ref: https://github.com/quic-go/quic-go/issues/4074#issuecomment-1713223709
	// udpConn, err := net.DialUDP(network, localUDPAddr, remoteUDPAddr)
	// if err != nil {
	// 	return err
	// }
	// defer udpConn.Close()

	udpConn, err := net.ListenUDP(network, udpAddrs.local)
	if err != nil {
		return err
	}
	defer udpConn.Close()

	tlsCfg := &tls.Config{
		NextProtos: []string{"h3"}, // ALPN
		ServerName: fQuic.TLSConfig.ServerName,
	}
	quicCfg := &quic.Config{}

	roundTripper := &http3.Transport{
		TLSClientConfig: tlsCfg,
		QUICConfig:      quicCfg,
		Dial: func(ctx context.Context, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			conn, e := quic.DialEarly(ctx, udpConn, udpAddrs.remote, tlsCfg, quicCfg)
			if e != nil {
				return nil, fmt.Errorf("xxx: %w", e)
			}
			return conn, e
		},
	}
	defer roundTripper.Close()

	httpClient := &http.Client{
		Transport: roundTripper,
	}

	u, err := url.JoinPath("https://", fHttp.Host, fHttp.Uri)
	if err != nil {
		return err
	}
	// TODO: そういえばPostとかボディ用のフォームを作ってない。作ったら下の第四引数に入れる
	req, err := http.NewRequestWithContext(ctx, fHttp.Method, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", fHttp.UserAgent)
	req.Header.Add("Accept", fHttp.Accept)

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}
