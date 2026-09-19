package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL3(ctx context.Context, selectedL3 string) error {
	ethernetFrame := &packemon.EthernetFrame{
		Header: s.packets.ethernet,
	}

	switch selectedL3 {
	case "ARP":
		ethernetFrame.Data = s.packets.arp.Bytes()
		return s.sendFn(ethernetFrame)
	case "IPv4":
		return s.sendOverIPv4(ctx, nil, ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "IPv6":
		return s.sendOverIPv6(ctx, nil, ethernetFrame, checkedCalcIPv6PayloadLength)
	default:
		return fmt.Errorf("not implemented form")
	}
}
