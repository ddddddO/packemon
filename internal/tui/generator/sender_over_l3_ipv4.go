package generator

import (
	"context"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverIPv4(
	ctx context.Context,
	upperLayerPacket []byte,
	ethernetFrame *packemon.EthernetFrame,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
) error {
	s.packets.ipv4.Data = upperLayerPacket
	if checkedCalcIPv4TotalLength {
		s.packets.ipv4.CalculateTotalLength()
	}
	if checkedCalcIPv4Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.ipv4.HeaderChecksum = 0x0
		s.packets.ipv4.CalculateChecksum()
	}
	ethernetFrame.Data = s.packets.ipv4.Bytes()
	return s.sendFn(ethernetFrame)
}
