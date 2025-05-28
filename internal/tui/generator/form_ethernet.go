package generator

import (
	"context"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var underIPv6 = false

func (g *generator) ethernetForm() *tview.Form {
	ethernetForm := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex)", DEFAULT_MAC_DESTINATION, 20, func(textToCheck string, lastChar rune) bool {
			// Support both hex format (0x prefix, 14 chars) and colon-separated format (17 chars)
			l := len(textToCheck)
			if l == 0 {
				return true
			}
			
			// Allow input up to 20 characters to support both formats
			if l > 20 {
				return false
			}

			// Try to parse the MAC address
			var b []byte
			var err error
			
			// Check if it's in colon-separated format
			if strings.Contains(textToCheck, ":") {
				// Convert colon-separated to hex format
				cleaned := strings.ReplaceAll(textToCheck, ":", "")
				if len(cleaned) > 12 {
					return false
				}
				b, err = packemon.StrHexToBytes("0x" + cleaned)
			} else {
				// Assume it's in hex format
				b, err = packemon.StrHexToBytes(textToCheck)
			}
			
			if err != nil {
				return false
			}
			g.sender.packets.ethernet.Dst = packemon.HardwareAddr(b)

			return true
		}, nil).
		AddInputField("Source Mac Addr(hex)", DEFAULT_MAC_SOURCE, 20, func(textToCheck string, lastChar rune) bool {
			// Support both hex format (0x prefix, 14 chars) and colon-separated format (17 chars)
			l := len(textToCheck)
			if l == 0 {
				return true
			}
			
			// Allow input up to 20 characters to support both formats
			if l > 20 {
				return false
			}

			// Try to parse the MAC address
			var b []byte
			var err error
			
			// Check if it's in colon-separated format
			if strings.Contains(textToCheck, ":") {
				// Convert colon-separated to hex format
				cleaned := strings.ReplaceAll(textToCheck, ":", "")
				if len(cleaned) > 12 {
					return false
				}
				b, err = packemon.StrHexToBytes("0x" + cleaned)
			} else {
				// Assume it's in hex format
				b, err = packemon.StrHexToBytes(textToCheck)
			}
			
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
