package generator

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var doTCP3wayHandshake = false

func (g *generator) tcpForm() *tview.Form {
	tcpForm := tview.NewForm().
		AddTextView("TCP", "This section generates the TCP.\nIt is still under development.", 60, 4, true, false).
		AddCheckbox("Do TCP 3way handshake ?", doTCP3wayHandshake, func(checked bool) {
			doTCP3wayHandshake = checked
		}).
		AddInputField("Source Port", DEFAULT_TCP_PORT_SOURCE, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				g.sender.packets.tcp.SrcPort = n
				return true
			}
			return false
		}, nil).
		AddInputField("Destination Port", DEFAULT_TCP_PORT_DESTINATION, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				g.sender.packets.tcp.DstPort = n
				return true
			}
			return false
		}, nil).
		AddInputField("Sequence", DEFAULT_TCP_SEQUENCE, 10, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 10 {
				return true
			} else if len(textToCheck) > 10 {
				return false
			}

			b, err := strHexToBytes3(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.tcp.Sequence = binary.BigEndian.Uint32(b)

			return true
		}, nil).
		AddInputField("Flags", DEFAULT_TCP_FLAGS, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := packemon.StrHexToBytes3(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.tcp.Flags = packemon.TCPFlags(b)

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

	return tcpForm
}
