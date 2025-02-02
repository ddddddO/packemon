package tui

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) dnsForm() *tview.Form {
	dnsForm := tview.NewForm().
		AddTextView("DNS", "This section generates the DNS.\nIt is still under development.", 60, 4, true, false).
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
			t.sender.packets.dns.TransactionID = binary.BigEndian.Uint16(b)

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
			t.sender.packets.dns.Flags = binary.BigEndian.Uint16(b)

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
			t.sender.packets.dns.Questions = binary.BigEndian.Uint16(b)

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
			t.sender.packets.dns.AnswerRRs = binary.BigEndian.Uint16(b)

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
			t.sender.packets.dns.AdditionalRRs = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Queries Domain", DEFAULT_DNS_QUERIES_DOMAIN, 64, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 64 {
				t.sender.packets.dns.Domain(textToCheck)
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
			t.sender.packets.dns.Queries.Typ = binary.BigEndian.Uint16(b)

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
			t.sender.packets.dns.Queries.Class = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("Send!", func() {
			if err := t.sender.send(context.TODO(), "L7"); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return dnsForm
}
