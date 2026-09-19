package generator

import (
	"context"
	"fmt"
)

func (s *sender) sendL4(ctx context.Context, selectedL4 string, selectedL3 string) error {
	switch selectedL4 {
	case "ICMPv4":
		return s.sendOverICMPv4(ctx, nil, selectedL3, checkedCalcICMPv4Timestamp, checkedCalcICMPv4Checksum, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "UDP":
		return s.sendOverUDP(ctx, nil, selectedL3, checkedCalcUDPChecksum, checkedCalcUDPLength, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum, checkedCalcIPv6PayloadLength)
	case "TCP":
		return s.sendOverTCP(ctx, nil, selectedL3, doTCP3wayHandshake, checkedCalcTCPChecksum, checkedCalcIPv4Checksum)
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL4)
	}
}
