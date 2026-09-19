package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendL7OverTLS12(
	ctx context.Context,
	selectedL4 string,
	selectedL3 string,
	doTCP3wayHandshake bool,
	doCustomOfTLSv12 bool,
) error {
	switch selectedL4 {
	case "TCP":
		if doTCP3wayHandshake {
			switch selectedL3 {
			case "":
				return fmt.Errorf("not implemented")
			case "IPv4":
				if doCustomOfTLSv12 {
					return packemon.EstablishTCPTLSv1_2AndSendPayload_CustomImpl(
						ctx,
						DEFAULT_NW_INTERFACE,
						s.packets.ethernet,
						s.packets.ipv4,
						s.packets.tcp,
						s.packets.http.Bytes(),
					)
				} else {
					return packemon.EstablishTCPTLSv1_2AndSendPayload(
						ctx,
						s.packets.ipv4,
						s.packets.tcp,
						s.packets.http.Bytes(),
					)
				}
			case "IPv6":
				if doCustomOfTLSv12 {
					return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6_CustomImpl(
						ctx,
						DEFAULT_NW_INTERFACE,
						s.packets.ethernet,
						s.packets.ipv6,
						s.packets.tcp,
						s.packets.http.Bytes(),
					)
				} else {
					return packemon.EstablishTCPTLSv1_2AndSendPayloadForIPv6(
						ctx,
						s.packets.ipv6,
						s.packets.tcp,
						s.packets.http.Bytes(),
					)
				}
			case "ARP":
				return fmt.Errorf("unsupported under protocol: %s", selectedL3)
			default:
				return fmt.Errorf("unsupported under protocol: %s", selectedL3)
			}
		} else {
			return fmt.Errorf("require tcp 3way handshake")
		}
	}

	return fmt.Errorf("not implemtented")
}
