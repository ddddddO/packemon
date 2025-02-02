package tui

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcUDPLength = false

func (t *tui) udpForm() *tview.Form {
	udpForm := tview.NewForm().
		AddTextView("UDP", "This section generates the UDP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Source Port", DEFAULT_UDP_PORT_SOURCE, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				t.sender.packets.udp.SrcPort = n
				return true
			}
			return false
		}, nil).
		AddInputField("Destination Port", DEFAULT_UDP_PORT_DESTINATION, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				t.sender.packets.udp.DstPort = n
				return true
			}
			return false
		}, nil).
		AddCheckbox("Automatically calculate length ?", checkedCalcUDPLength, func(checked bool) {
			checkedCalcUDPLength = checked
		}).
		AddInputField("Length", DEFAULT_UDP_LENGTH, 6, func(textToCheck string, lastChar rune) bool {
			if checkedCalcUDPLength {
				return false
			}

			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			t.sender.packets.udp.Length = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			if err := t.sender.send(context.TODO(), "L4"); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return udpForm
}
