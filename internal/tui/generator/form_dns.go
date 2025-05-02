package generator

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var do3wayHandshakeForDNS = false

func (g *generator) dnsForm() *tview.Form {
	dnsForm := tview.NewForm().
		AddTextView("DNS", "This section generates the DNS.\nIt is still under development.", 60, 4, true, false).
		AddCheckbox("Do TCP 3way handshake ?", do3wayHandshakeForDNS, func(checked bool) {
			do3wayHandshakeForDNS = checked
		}).
		AddInputField("Transaction ID", DEFAULT_DNS_TRANSACTION, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.TransactionID = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Flags", DEFAULT_DNS_FLAGS, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.Flags = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Questions", DEFAULT_DNS_QUESTIONS, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.Questions = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("AnswerRRs", DEFAULT_DNS_ANSWERS_RRs, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.AnswerRRs = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("AdditionalRRs", DEFAULT_DNS_ADDITIONAL_RRs, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.AdditionalRRs = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Queries Domain", DEFAULT_DNS_QUERIES_DOMAIN, 64, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 64 {
				g.sender.packets.dns.Domain(textToCheck)
				return true
			}
			return false
		}, nil).
		AddInputField("Querys Type", DEFAULT_DNS_QUERIES_TYPE, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.Queries.Typ = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Queries Class", DEFAULT_DNS_QUERIES_CLASS, 6, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 6 {
				return true
			} else if len(textToCheck) > 6 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			g.sender.packets.dns.Queries.Class = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer7(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return dnsForm
}
