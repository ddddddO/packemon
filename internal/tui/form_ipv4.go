package tui

import (
	"context"
	"encoding/binary"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) ipv4Form() *tview.Form {
	ipv4Form := tview.NewForm().
		AddTextView("IPv4 Header", "This section generates the IPv4 header.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Version(hex)", "0x04", 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := packemon.StrHexToBytes(textToCheck)
			if err != nil {
				return false
			}
			t.sender.packets.ipv4.Version = uint8(binary.BigEndian.Uint16(b))

			return true
		}, nil).
		AddDropDown("Protocol", []string{"ICMP", "UDP", "TCP"}, 1, func(selected string, _ int) {
			switch selected {
			case "ICMP":
				t.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_ICMP
			case "UDP":
				t.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_UDP
			case "TCP":
				t.sender.packets.ipv4.Protocol = packemon.IPv4_PROTO_TCP
			}
		}).
		AddInputField("Source IP Addr", DEFAULT_IP_SOURCE, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := packemon.StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				t.sender.packets.ipv4.SrcAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddInputField("Destination IP Addr", DEFAULT_IP_DESTINATION, 15, func(textToCheck string, lastChar rune) bool {
			count := strings.Count(textToCheck, ".")
			if count < 3 {
				return true
			} else if count == 3 {
				ip, err := packemon.StrIPToBytes(textToCheck)
				if err != nil {
					return false
				}
				t.sender.packets.ipv4.DstAddr = binary.BigEndian.Uint32(ip)
				return true
			}

			return false
		}, nil).
		AddButton("Send!", func() {
			if err := t.sender.sendLayer3(context.TODO()); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ipv4Form
}
