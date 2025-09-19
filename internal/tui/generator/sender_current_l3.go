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
		if checkedCalcIPv4TotalLength {
			s.packets.ipv4.CalculateTotalLength()
		}
		if checkedCalcIPv4Checksum {
			s.packets.ipv4.HeaderChecksum = 0x0
			s.packets.ipv4.CalculateChecksum()
		}
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   s.packets.ipv4.Bytes(),
		})
	case "IPv6":
		s.packets.ipv6.Data = []byte{} // 前回分の IPv6 より上のデータをクリア
		if checkedCalcIPv6PayloadLength {
			s.packets.ipv6.CalculatePayloadLength()
		}
		return s.sendFn(&packemon.EthernetFrame{
			Header: s.packets.ethernet,
			Data:   s.packets.ipv6.Bytes(),
		})
	default:
		return fmt.Errorf("not implemented form")
	}
}
