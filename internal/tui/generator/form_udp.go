package generator

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcUDPLength = true
var checkedCalcUDPChecksum = true

func (g *generator) udpForm() *tview.Form {
	udpForm := tview.NewForm().
		AddTextView("UDP", "This section generates the UDP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Source Port", DEFAULT_UDP_PORT_SOURCE, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				g.sender.packets.udp.SrcPort = n
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
				g.sender.packets.udp.DstPort = n
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
			g.sender.packets.udp.Length = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddCheckbox("Automatically calculate checksum ?", checkedCalcUDPChecksum, func(checked bool) {
			checkedCalcUDPChecksum = checked
		}).
		AddInputField("Checksum", DEFAULT_UDP_CHECKSUM, 6, func(textToCheck string, lastChar rune) bool {
			if checkedCalcUDPChecksum {
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
			g.sender.packets.udp.Checksum = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer4(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return udpForm
}
