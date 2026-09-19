package generator

import (
	"context"
	"fmt"
)

func (s *sender) sendOverL4(
	ctx context.Context,
	upperLayerPacket []byte,
	upperLayerPacketForTCP []byte,
	selectedL4 string,
	selectedL3 string,
	checkedCalcICMPTimestamp bool,
	checkedCalcICMPChecksum bool,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
	checkedCalcUDPChecksum bool,
	checkedCalcUDPLength bool,
	checkedCalcIPv6PayloadLength bool,
	doTCP3wayHandshake bool,
	checkedCalcTCPChecksum bool,
) error {
	switch selectedL4 {
	case "ICMP":
		return s.sendOverICMPv4(ctx, upperLayerPacket, selectedL3, checkedCalcICMPTimestamp, checkedCalcICMPChecksum, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "UDP":
		return s.sendOverUDP(ctx, upperLayerPacket, selectedL3, checkedCalcUDPChecksum, checkedCalcUDPLength, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum, checkedCalcIPv6PayloadLength)
	case "TCP":
		return s.sendOverTCP(ctx, upperLayerPacketForTCP, selectedL3, doTCP3wayHandshake, checkedCalcTCPChecksum, checkedCalcIPv4Checksum)
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL4)
	}
}
