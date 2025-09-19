package generator

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPChecksum = true
var checkedCalcICMPTimestamp = false

func (g *generator) icmpForm() *tview.Form {
	icmpForm := tview.NewForm().
		AddTextView("ICMP", "This section generates ICMP.", 60, 3, true, false).
		AddInputField("Type", DEFAULT_ICMP_TYPE, 4, func(textToCheck string, lastChar rune) bool {
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
		AddInputField("Code", DEFAULT_ICMP_CODE, 4, func(textToCheck string, lastChar rune) bool {
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
		AddCheckbox("Automatically calculate checksum ?", checkedCalcICMPChecksum, func(checked bool) {
			checkedCalcICMPChecksum = checked
		}).
		AddInputField("Checksum", DEFAULT_ICMP_CHECKSUM, 6, func(textToCheck string, lastChar rune) bool {
			if checkedCalcICMPChecksum {
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
			g.sender.packets.icmpv4.Checksum = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Identifier", DEFAULT_ICMP_IDENTIFIER, 6, func(textToCheck string, lastChar rune) bool {
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
		AddInputField("Sequence", DEFAULT_ICMP_SEQUENCE, 6, func(textToCheck string, lastChar rune) bool {
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
		// Timestamp request(Type=13) で必要なタイムスタンプ群をData部に追加するときにチェックする
		AddCheckbox("Automatically add timestamp ?", checkedCalcICMPTimestamp, func(checked bool) {
			checkedCalcICMPTimestamp = checked
		}).
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
