package generator

import (
	"context"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverIPv6(
	ctx context.Context,
	upperLayerPacket []byte,
	ethernetFrame *packemon.EthernetFrame,
	checkedCalcIPv6PayloadLength bool,
) error {
	s.packets.ipv6.Data = upperLayerPacket
	if checkedCalcIPv6PayloadLength {
		s.packets.ipv6.CalculatePayloadLength()
	}
	ethernetFrame.Data = s.packets.ipv6.Bytes()
	return s.sendFn(ethernetFrame)
}
