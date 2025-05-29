package generator

import (
	"context"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var underIPv6 = false

// validateAndParseMACAddress validates and parses MAC address input
// Supports both hex format (0x prefix) and colon-separated format
func validateAndParseMACAddress(input string) (packemon.HardwareAddr, bool) {
	l := len(input)
	
	if l > 20 {
		return nil, false
	}

	// Only try to parse when we have enough characters for a potential MAC address
	// Minimum: "0x" + 12 hex chars = 14, or XX:XX:XX:XX:XX:XX = 17
	if l >= 14 || (strings.Contains(input, ":") && l >= 17) {
		var b []byte
		var err error
		
		if strings.Contains(input, ":") {
			cleaned := strings.ReplaceAll(input, ":", "")
			if len(cleaned) > 12 {
				return nil, false
			}
			b, err = packemon.StrHexToBytes("0x" + cleaned)
		} else {
			b, err = packemon.StrHexToBytes(input)
		}
		
		if err == nil {
			return packemon.HardwareAddr(b), true
		}
	}

	return nil, true // Return true to allow continued typing
}

func (g *generator) ethernetForm() *tview.Form {
	ethernetForm := tview.NewForm().
		AddTextView("Ethernet Header", "This section generates the Ethernet header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Destination Mac Addr(hex)", DEFAULT_MAC_DESTINATION, 20, func(textToCheck string, lastChar rune) bool {
			// Support both hex format (0x prefix, 14 chars) and colon-separated format (17 chars)
			addr, valid := validateAndParseMACAddress(textToCheck)
			if !valid {
				return false
			}
			if addr != nil {
				g.sender.packets.ethernet.Dst = addr
			}
			return true
		}, nil).
		AddInputField("Source Mac Addr(hex)", DEFAULT_MAC_SOURCE, 20, func(textToCheck string, lastChar rune) bool {
			// Support both hex format (0x prefix, 14 chars) and colon-separated format (17 chars)
			addr, valid := validateAndParseMACAddress(textToCheck)
			if !valid {
				return false
			}
			if addr != nil {
				g.sender.packets.ethernet.Src = addr
			}
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
