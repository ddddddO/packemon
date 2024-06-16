package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) ethernetForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader) *tview.Form {
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
			ethernetHeader.Dst = packemon.HardwareAddr(b)

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
			ethernetHeader.Src = packemon.HardwareAddr(b)

			return true
		}, nil).
		// TODO: 自由にフレーム作れるとするなら、ここもhexで受け付けるようにして、IP or ARPヘッダフォームへの切り替えも自由にできた方がいいかも
		AddDropDown("Ether Type", []string{"IPv4", "ARP"}, 0, func(selected string, _ int) {
			switch selected {
			case "IPv4":
				ethernetHeader.Typ = packemon.ETHER_TYPE_IPv4
			case "ARP":
				ethernetHeader.Typ = packemon.ETHER_TYPE_ARP
			}
		}).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				// data: 専用の口用意してユーザー自身の任意のフレームを送れるようにする？,
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Over layer", func() {
			switch ethernetHeader.Typ {
			case packemon.ETHER_TYPE_IPv4:
				t.pages.SwitchToPage("IPv4")
			case packemon.ETHER_TYPE_ARP:
				t.pages.SwitchToPage("ARP")
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return ethernetForm
}
