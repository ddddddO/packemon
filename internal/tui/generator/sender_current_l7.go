package generator

import (
	"context"
	"fmt"
)

func (s *sender) sendL7(ctx context.Context, selectedL7, selectedL5_6, selectedL4, selectedL3 string) error {
	switch selectedL7 {
	case "DNS":
		switch selectedL5_6 {
		case "":
			return s.sendOverL4(
				ctx,
				s.packets.dns.Bytes(),
				s.packets.dns.BytesForTCP(),
				selectedL4,
				selectedL3,
				checkedCalcICMPv4Timestamp,
				checkedCalcICMPv4Checksum,
				checkedCalcIPv4TotalLength,
				checkedCalcIPv4Checksum,
				checkedCalcUDPChecksum,
				checkedCalcUDPLength,
				checkedCalcIPv6PayloadLength,
				doTCP3wayHandshake,
				checkedCalcTCPChecksum,
			)
		case "TLSv1.2":
			return s.sendL7OverTLS12(ctx, s.packets.dns.BytesForTCP(), selectedL4, selectedL3, doTCP3wayHandshake, doCustomOfTLSv12)
		case "TLSv1.3":
			return s.sendL7OverTLS13(ctx, s.packets.dns.BytesForTCP(), selectedL4, selectedL3, doTCP3wayHandshake, doCustomOfTLSv13)
		default:
			return fmt.Errorf("unsupported under protocol: %s", selectedL5_6)
		}

	case "HTTP":
		switch selectedL5_6 {
		case "":
			return s.sendOverL4(
				ctx,
				s.packets.http.Bytes(),
				s.packets.http.Bytes(),
				selectedL4,
				selectedL3,
				checkedCalcICMPv4Timestamp,
				checkedCalcICMPv4Checksum,
				checkedCalcIPv4TotalLength,
				checkedCalcIPv4Checksum,
				checkedCalcUDPChecksum,
				checkedCalcUDPLength,
				checkedCalcIPv6PayloadLength,
				doTCP3wayHandshake,
				checkedCalcTCPChecksum,
			)
		case "TLSv1.2":
			return s.sendL7OverTLS12(ctx, s.packets.http.Bytes(), selectedL4, selectedL3, doTCP3wayHandshake, doCustomOfTLSv12)
		case "TLSv1.3":
			return s.sendL7OverTLS13(ctx, s.packets.http.Bytes(), selectedL4, selectedL3, doTCP3wayHandshake, doCustomOfTLSv13)
		case "QUIC":
			// TODO: sendL7QuicがHTTP専用になってる
			return s.sendL7Quic(ctx, selectedL4, selectedL3)
		}
		return fmt.Errorf("not implemtented")

	default:
		return fmt.Errorf("unsupported protocol: %s", selectedL7)
	}
}
