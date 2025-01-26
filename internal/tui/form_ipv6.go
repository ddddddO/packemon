package tui

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) ipv6Form(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv6 *packemon.IPv6) *tview.Form {
	ipv6Form := tview.NewForm().
		AddTextView("IPv6 Header", "This section generates the IPv6 header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Version(hex)", "0x06", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			ipv6.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddDropDown("Next Header", []string{"ICMPv6", "UDP", "TCP"}, 0, func(selected string, _ int) {
			switch selected {
			case "ICMPv6":
				// TODO: 未実装
				t.addErrPage(fmt.Errorf("%s\n", "under development"))
				// ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_ICMPv6
			case "UDP":
				ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_UDP
			case "TCP":
				ipv6.NextHeader = packemon.IPv6_NEXT_HEADER_TCP
			}
		}).
		AddInputField("Source IP Addr", DEFAULT_IPv6_SOURCE, 39, func(textToCheck string, lastChar rune) bool {
			ip := net.ParseIP(textToCheck)
			if ip != nil {
				ipv6.SrcAddr = ip.To16()
			}
			return true

		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IPv6_DESTINATION, 39, func(textToCheck string, lastChar rune) bool {
			ip := net.ParseIP(textToCheck)
			if ip != nil {
				ipv6.DstAddr = ip.To16()
			}
			return true

		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			ipv6.Data = []byte{} // 前回分の IPv6 より上のデータをクリア
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv6.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Under layer", func() {
			t.pages.SwitchToPage("Ethernet")
		}).
		AddButton("Over layer", func() {
			switch ipv6.NextHeader {
			case packemon.IPv6_NEXT_HEADER_ICMPv6:
				// TODO: 未実装
				t.addErrPage(fmt.Errorf("%s\n", "under development"))
				// t.pages.SwitchToPage("ICMPv6")
			case packemon.IPv6_NEXT_HEADER_UDP:
				t.pages.SwitchToPage("UDP")
			case packemon.IPv6_NEXT_HEADER_TCP:
				t.pages.SwitchToPage("TCP")
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ipv6Form
}
