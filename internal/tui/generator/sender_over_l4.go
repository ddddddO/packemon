package generator

import (
	"context"
	"fmt"
)

// TODO: sender_current_l4.goと共通化
func (s *sender) sendOverL4(
	ctx context.Context,
	upperLayerPacket []byte,
	upperLayerPacketForTCP []byte,
	selectedL4 string,
	selectedL3 string,
	checkedCalcICMPv4Timestamp bool,
	checkedCalcICMPv4Checksum bool,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
	checkedCalcUDPChecksum bool,
	checkedCalcUDPLength bool,
	checkedCalcIPv6PayloadLength bool,
	doTCP3wayHandshake bool,
	checkedCalcTCPChecksum bool,
) error {
	switch selectedL4 {
	case "ICMPv4":
		return s.sendOverICMPv4(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv4Timestamp, checkedCalcICMPv4Checksum, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case SELECTABLE_FORM_ICMPv6_ECHO_REQUEST_ECHO_REPLY:
		return s.sendOverICMPv6Echo(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6EchoRequestEchoReplyChecksum, checkedCalcIPv6PayloadLength)
	case SELECTABLE_FORM_ICMPv6_NEIGHBOR_SOLICITATION:
		return s.sendOverICMPv6NeighborSolicitation(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6NeighborSolicitationChecksum, checkedCalcIPv6PayloadLength)
	case SELECTABLE_FORM_ICMPv6_NEIGHBOR_ADVERTISEMENT:
		return s.sendOverICMPv6NeighborAdvertisement(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6NeighborAdvertisementChecksum, checkedCalcIPv6PayloadLength)
	case SELECTABLE_FORM_ICMPv6_ROUTER_SOLICITATION:
		return s.sendOverICMPv6RouterSolicitation(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6RouterSolicitationChecksum, checkedCalcIPv6PayloadLength)
	case SELECTABLE_FORM_ICMPv6_ROUTER_ADVERTISEMENT:
		return s.sendOverICMPv6RouterAdvertisement(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6RouterAdvertisementChecksum, checkedCalcIPv6PayloadLength)
	case SELECTABLE_FORM_ICMPv6_REDIRECT:
		return s.sendOverICMPv6Redirect(ctx, upperLayerPacket, selectedL3, checkedCalcICMPv6RedirectChecksum, checkedCalcIPv6PayloadLength)
	case "UDP":
		return s.sendOverUDP(ctx, upperLayerPacket, selectedL3, checkedCalcUDPChecksum, checkedCalcUDPLength, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum, checkedCalcIPv6PayloadLength)
	case "TCP":
		return s.sendOverTCP(ctx, upperLayerPacketForTCP, selectedL3, doTCP3wayHandshake, checkedCalcTCPChecksum, checkedCalcIPv4Checksum)
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL4)
	}
}
