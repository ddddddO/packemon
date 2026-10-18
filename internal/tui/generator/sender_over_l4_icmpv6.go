package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

// TODO:  共通化

func (s *sender) sendOverICMPv6NeighborSolicitation(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6NeighborSolicitation.Options = append(s.packets.icmpv6NeighborSolicitation.Options, upperLayerPacket...)
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6NeighborSolicitation.Header.Checksum = 0x0
		s.packets.icmpv6NeighborSolicitation.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6NeighborSolicitation.Bytes(),
		)
	}

	return s.sendOverL3ForICMPv6(
		ctx,
		selectedL3,
		s.packets.icmpv6NeighborSolicitation.Bytes(),
		checkedCalcIPv4TotalLength,
		checkedCalcIPv4Checksum,
		checkedCalcIPv6PayloadLength,
	)
}

func (s *sender) sendOverICMPv6NeighborAdvertisement(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6NeighborAdvertisement.Options = append(s.packets.icmpv6NeighborAdvertisement.Options, upperLayerPacket...)
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6NeighborAdvertisement.Header.Checksum = 0x0
		s.packets.icmpv6NeighborAdvertisement.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6NeighborAdvertisement.Bytes(),
		)
	}

	return s.sendOverL3ForICMPv6(
		ctx,
		selectedL3,
		s.packets.icmpv6NeighborAdvertisement.Bytes(),
		checkedCalcIPv4TotalLength,
		checkedCalcIPv4Checksum,
		checkedCalcIPv6PayloadLength,
	)
}

func (s *sender) sendOverICMPv6RouterSolicitation(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6RouterSolicitation.Options = append(s.packets.icmpv6RouterSolicitation.Options, upperLayerPacket...)
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6RouterSolicitation.Header.Checksum = 0x0
		s.packets.icmpv6RouterSolicitation.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6RouterSolicitation.Bytes(),
		)
	}

	return s.sendOverL3ForICMPv6(
		ctx,
		selectedL3,
		s.packets.icmpv6RouterSolicitation.Bytes(),
		checkedCalcIPv4TotalLength,
		checkedCalcIPv4Checksum,
		checkedCalcIPv6PayloadLength,
	)
}

func (s *sender) sendOverICMPv6RouterAdvertisement(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6RouterAdvertisement.Options = append(s.packets.icmpv6RouterAdvertisement.Options, upperLayerPacket...)
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6RouterAdvertisement.Header.Checksum = 0x0
		s.packets.icmpv6RouterAdvertisement.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6RouterAdvertisement.Bytes(),
		)
	}

	return s.sendOverL3ForICMPv6(
		ctx,
		selectedL3,
		s.packets.icmpv6RouterAdvertisement.Bytes(),
		checkedCalcIPv4TotalLength,
		checkedCalcIPv4Checksum,
		checkedCalcIPv6PayloadLength,
	)
}

func (s *sender) sendOverICMPv6Redirect(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPv6Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	if len(upperLayerPacket) > 0 {
		s.packets.icmpv6Redirect.Options = append(s.packets.icmpv6Redirect.Options, upperLayerPacket...)
	}

	if checkedCalcICMPv6Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv6Redirect.Header.Checksum = 0x0
		s.packets.icmpv6Redirect.Header.Checksum = packemon.CalculateChecksumICMPv6(
			s.packets.ipv6,
			s.packets.icmpv6Redirect.Bytes(),
		)
	}

	return s.sendOverL3ForICMPv6(
		ctx,
		selectedL3,
		s.packets.icmpv6Redirect.Bytes(),
		checkedCalcIPv4TotalLength,
		checkedCalcIPv4Checksum,
		checkedCalcIPv6PayloadLength,
	)
}

func (s *sender) sendOverL3ForICMPv6(
	ctx context.Context,
	selectedL3 string,
	icmpPayload []byte,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
	checkedCalcIPv6PayloadLength bool,
) error {
	ethernetFrame := &packemon.EthernetFrame{
		Header: s.packets.ethernet,
	}

	switch selectedL3 {
	case "IPv4":
		return s.sendOverIPv4(ctx, icmpPayload, ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "IPv6":
		return s.sendOverIPv6(ctx, icmpPayload, ethernetFrame, checkedCalcIPv6PayloadLength)
	case "ARP":
		return fmt.Errorf("unsupported under ARP")
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL3)
	}
}
