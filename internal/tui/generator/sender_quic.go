package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL7Quic(
	ctx context.Context,
	selectedL4 string,
	selectedL3 string,
) error {
	switch selectedL4 {
	case "UDP":
		switch selectedL3 {
		case "":
			return fmt.Errorf("not implemented")
		case "IPv4":
			return packemon.SendUDP_QUIC_HTTP_Payload(
				ctx,
				s.packets.ipv4,
				s.packets.udp,
				s.packets.quic,
				s.packets.http,
			)
		case "IPv6":
			return packemon.SendUDP_QUIC_HTTP_PayloadForIPv6(
				ctx,
				s.packets.ipv6,
				s.packets.udp,
				s.packets.quic,
				s.packets.http,
			)
		default:
			return fmt.Errorf("unsupported under protocol: %s", selectedL3)
		}
	}
	return fmt.Errorf("not implemtented")
}
