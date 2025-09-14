package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL3(ctx context.Context, selectedL3 string) error {
	switch selectedL3 {
	case "ARP":
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   s.packets.arp.Bytes(),
		})
	case "IPv4":
		s.packets.ipv4.Data = []byte{} // 前回分の IPv4 より上のデータをクリア
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   s.packets.ipv4.Bytes(),
		})
	case "IPv6":
		s.packets.ipv6.Data = []byte{} // 前回分の IPv6 より上のデータをクリア
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   s.packets.ipv6.Bytes(),
		})
	default:
		return fmt.Errorf("not implemented form")
	}
}
