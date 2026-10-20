//go:build linux
// +build linux

package packemon

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"

	"golang.org/x/sys/unix"
)

func NewInterfaceDevices() (InterfaceDevices, error) {
	ids := []*InterfaceDevice{}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, intf := range interfaces {
		ipAddrs, err := intf.Addrs()
		if err != nil {
			return nil, err
		}
		addrs := make([]string, len(ipAddrs))
		for i, addr := range ipAddrs {
			addrs[i] = strings.Split(addr.String(), "/")[0]
		}

		id := &InterfaceDevice{
			InterfaceName: intf.Name,
			MacAddr:       intf.HardwareAddr.String(),
			IPAddrs:       addrs,
		}
		ids = append(ids, id)
	}

	return ids, nil
}

type NetworkInterface struct {
	Intf       *net.Interface
	Socket     int // file discripter
	SocketAddr unix.SockaddrLinklayer
	IPAdder    uint32

	PassiveCh chan *Passive
}

func newNetworkInterface(nwInterface string) (*NetworkInterface, error) {
	intf, err := getInterface(nwInterface)
	if err != nil {
		return nil, err
	}
	ipAddrs, err := intf.Addrs()
	if err != nil {
		return nil, err
	}
	if len(ipAddrs) == 0 {
		return nil, errors.New("network interface may not have IP address configured")
	}

	// FIXME: IPv6で、「strconv.ParseUint: parsing "fe80::cc88:acff:fee5:73fd"」のエラーが出ていた
	//　 　　　現状、ipAddrは使われてないので、パース失敗しても実害はない。なので一旦errを無視する
	ipAddr, err := StrIPToBytes(strings.Split(ipAddrs[0].String(), "/")[0])
	_, _ = ipAddr, err
	// if err != nil {
	// 	return nil, err
	// }

	// https://ja.manpages.org/af_packet/7 のリンク先に、以下コード1行分の説明あり. ためになる.
	// https://github.com/pandax381/seccamp2024 の README にリンクされているスライドもためになる(「KLab Expert Camp 6 - Day3」のとこ).
	// また、上記スライドに各OSで直接Ethernetフレームを送受信する手段についてもヒントあり.
	sock, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(hton(unix.ETH_P_ALL)))
	if err != nil {
		return nil, err
	}

	addr := unix.SockaddrLinklayer{
		Protocol: hton(unix.ETH_P_ALL),
		Ifindex:  intf.Index,
	}

	if err := unix.Bind(sock, &addr); err != nil {
		return nil, err
	}

	return &NetworkInterface{
		Intf:       intf,
		Socket:     sock,
		SocketAddr: addr,
		// IPAdder:    binary.BigEndian.Uint32(ipAddr), // FIXME: どこにも使われてなかったからわからなかったけど、IPv6アドレスだとダメ

		PassiveCh: make(chan *Passive, 100),
	}, nil
}

func getInterface(nwInterface string) (*net.Interface, error) {
	// any で全てのインタフェースを取得しない限り、net.InterfaceByName で取得がいいかもしれない
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var intf *net.Interface
	for i := range interfaces {
		if interfaces[i].Name == nwInterface {
			intf = &interfaces[i]
		}
	}
	if intf == nil {
		return nil, errors.New("specified interface did not exist")
	}

	return intf, nil
}

func (nw *NetworkInterface) send(ethernetFrame *EthernetFrame) error {
	return unix.Sendto(nw.Socket, ethernetFrame.Bytes(), 0, &nw.SocketAddr)
}

func (nw *NetworkInterface) recieve(ctx context.Context, shouldParseFull bool) error {
	// MTU 1500 の最大フレーム（1514バイト）や GRO / TSO で結合されたパケットも切り詰めないよう、
	// mac/win（pcap.OpenLive の snaplen）とそろえて 65536 バイトにする
	recieved := make([]byte, 65536)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			n, _, err := unix.Recvfrom(nw.Socket, recieved, 0)
			if err != nil {
				if n == -1 {
					continue
				}
				return err
			}

			// パース結果は受信データを参照し続けるため、受信したバイト数分だけコピーして渡す（受信バッファは使い回す）
			nw.PassiveCh <- ParsedPacket(bytes.Clone(recieved[:n]), shouldParseFull)
		}
	}
}

func (nw *NetworkInterface) close() error {
	return unix.Close(nw.Socket)
}
