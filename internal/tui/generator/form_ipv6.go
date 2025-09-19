package generator

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcIPv6PayloadLength = true

func (g *generator) ipv6Form() *tview.Form {
	ipv6Form := tview.NewForm().
		AddTextView("IPv6 Header", "This section generates IPv6.", 60, 3, true, false).
		AddInputField("Version", "0x06", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv6.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddInputField("Traffic Class", DEFAULT_IPv6_TRAFFIC_CLASS, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv6.TrafficClass = uint8(b)

			return true
		}, nil).
		AddInputField("Flow Label", DEFAULT_IPv6_FLOW_LABEL, 7, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 7 {
				return true
			} else if len(textToCheck) > 7 {
				return false
			}

			// TODO: 要確認
			n, err := strconv.ParseUint(textToCheck, 0, 20)
			if err != nil {
				return false
			}
			g.sender.packets.ipv6.FlowLabel = uint32(n)

			return true
		}, nil).
		AddCheckbox("Automatically calculate payload length ?", checkedCalcIPv6PayloadLength, func(checked bool) {
			checkedCalcIPv6PayloadLength = checked
		}).
		AddInputField("Payload Length", DEFAULT_IPv6_PAYLOAD_LENGTH, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv6.PayloadLength = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddDropDown("Next Header", []string{"ICMPv6", "UDP", "TCP"}, 0, func(selected string, _ int) {
			switch selected {
			case "ICMPv6":
				// TODO: 未実装
				g.addErrPage(fmt.Errorf("%s\n", "under development"))
				// ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_ICMPv6
			case "UDP":
				g.sender.packets.ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_UDP
			case "TCP":
				g.sender.packets.ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_TCP
			}
		}).
		AddInputField("Hop Limit", DEFAULT_IPv6_HOP_LIMIT, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ipv6.HopLimit = uint8(b)

			return true
		}, nil).
		AddInputField("Source IP Addr", DEFAULT_IPv6_SOURCE, 39, func(textToCheck string, lastChar rune) bool {
			ip := net.ParseIP(textToCheck)
			if ip != nil {
				g.sender.packets.ipv6.SrcAddr = ip.To16()
			}
			return true

		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IPv6_DESTINATION, 39, func(textToCheck string, lastChar rune) bool {
			ip := net.ParseIP(textToCheck)
			if ip != nil {
				g.sender.packets.ipv6.DstAddr = ip.To16()
			}
			return true

		}, nil).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer3(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ipv6Form
}
