package tui

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (g *generator) icmpForm() *tview.Form {
	icmpForm := tview.NewForm().
		AddTextView("ICMP", "This section generates the ICMP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Type(hex)", DEFAULT_ICMP_TYPE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.icmpv4.Typ = uint8(b)

			return true
		}, nil).
		AddInputField("Code(hex)", DEFAULT_ICMP_CODE, 4, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 4 {
				return true
			} else if len(textToCheck) > 4 {
				return false
			}

			b, err := strHexToUint8(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.icmpv4.Code = uint8(b)

			return true
		}, nil).
		AddInputField("Identifier(hex)", DEFAULT_ICMP_IDENTIFIER, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.icmpv4.Identifier = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Sequence(hex)", DEFAULT_ICMP_SEQUENCE, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.icmpv4.Sequence = binary.BigEndian.Uint16(b)

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

	return icmpForm
}
