package tui

import (
	"encoding/binary"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) ipv4Form(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4) *tview.Form {
	ipv4Form := tview.NewForm().
		AddTextView("IPv4 Header", "This section generates the IPv4 header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Version(hex)", "0x04", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			ipv4.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddDropDown("Protocol", []string{"ICMP", "UDP"}, 0, func(selected string, _ int) {
			switch selected {
			case "ICMP":
				ipv4.Protocol = packemon.IPv4_PROTO_ICMP
			case "UDP":
				ipv4.Protocol = packemon.IPv4_PROTO_UDP
			}
		}).
		AddInputField("Source IP Addr", DEFAULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.SrcAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := strIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				ipv4.DstAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.app.Stop()
			}
		}).
		AddButton("Under layer", func() {
			t.pages.SwitchToPage("Ethernet")
		}).
		AddButton("Over layer", func() {
			switch ipv4.Protocol {
			case packemon.IPv4_PROTO_ICMP:
				t.pages.SwitchToPage("ICMP")
			case packemon.IPv4_PROTO_UDP:
				// TODO:
				// pages.SwitchToPage("UDP")
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ipv4Form
}
