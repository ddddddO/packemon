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
	checkedCalcICMPv4Timestamp bool,
	checkedCalcICMPv4Checksum bool,
	checkedCalcIPv4TotalLength bool,
	checkedCalcIPv4Checksum bool,
) error {
	// このブロックは ICMPv4 の Data部の入力仕様
	// データ部へは以下の優先順位で埋まる
	//   1: ICMPv4 フォームで、タイムスタンプ付加有効時タイムスタンプ格納
	//   2: ICMPv4 が選択され上位レイヤで送信された場合に上位レイヤのペイロード格納
	//   3: ICMPv4 フォームで、Data フォームに入力された値を格納
	if checkedCalcICMPv4Timestamp {
		s.packets.icmpv4.Data = s.packets.icmpv4.TimestampForTypeTimestampRequest()
	} else {
		if len(upperLayerPacket) > 0 {
			s.packets.icmpv4.Data = upperLayerPacket
		}
	}

	if checkedCalcICMPv4Checksum {
		// 前回Send分が残ってると計算誤るため
		s.packets.icmpv4.Header.Checksum = 0x0
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
