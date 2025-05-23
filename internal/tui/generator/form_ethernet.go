package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var underIPv6 = false

func (g *generator) ethernetForm() *tview.Form {
	ethernetForm := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex)", DEFAULT_MAC_DESTINATION, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ethernet.Dst = packemon.HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Source Mac Addr(hex)", DEFAULT_MAC_SOURCE, 14, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 14 {
				return true
			} else if len(textToCheck) > 14 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.ethernet.Src = packemon.HardwareAddr(b)

			return true
		}, nil).
		// TODO: 自由にフレーム作れるとするなら、ここもhexで受け付けるようにして、IP or ARPヘッダフォームへの切り替えも自由にできた方がいいかも
		AddDropDown("Ether Type", []string{"IPv4", "IPv6", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_IPv4
				underIPv6 = false
			case "IPv6":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_IPv6
				underIPv6 = true
			case "ARP":
				g.sender.packets.ethernet.Typ = packemon.ETHER_TYPE_ARP
				underIPv6 = false
			}
		}).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer2(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ethernetForm
}
