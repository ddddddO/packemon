package generator

import (
	"context"
	"fmt"

	"github.com/ddddddO/packemon"
)

func (s *sender) sendOverICMPv4(
	ctx context.Context,
	upperLayerPacket []byte,
	selectedL3 string,
	checkedCalcICMPTimestamp bool,
	checkedCalcICMPChecksum bool,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
) error {
	s.packets.icmpv4.Data = []byte{}
	if checkedCalcICMPTimestamp {
		s.packets.icmpv4.Data = s.packets.icmpv4.TimestampForTypeTimestampRequest()
	} else {
		// TODO: 動作確認がまだだし、フォームでcheckedCalcICMPTimestampがoffの時に上位レイヤのデータが入るという説明がないので足した方がいい
		//       いやもう少し考えた方が良いかも。上位レイヤ有りかつcheckedCalcICMPTimestampがonで、両方格納とか...？
		s.packets.icmpv4.Data = upperLayerPacket
	}
	if checkedCalcICMPChecksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv4.Checksum = 0x0
		s.packets.icmpv4.CalculateChecksum()
	}

	ethernetFrame := &packemon.EthernetFrame{
		Header: s.packets.ethernet,
	}

	switch selectedL3 {
	case "IPv4":
		return s.sendOverIPv4(ctx, s.packets.icmpv4.Bytes(), ethernetFrame, checkedCalcIPv4TotalLength, checkedCalcIPv4Checksum)
	case "IPv6":
		return s.sendOverIPv6(ctx, s.packets.icmpv4.Bytes(), ethernetFrame, checkedCalcIPv6PayloadLength)
	case "ARP":
		return fmt.Errorf("unsupported under ARP")
	default:
		return fmt.Errorf("not implemented under protocol: %s", selectedL3)
	}
}
