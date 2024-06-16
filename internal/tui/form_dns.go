package tui

import (
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) dnsForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, udp *packemon.UDP, dns *packemon.DNS) *tview.Form {
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
			dns.TransactionID = binary.BigEndian.Uint16(b)

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
			dns.Flags = binary.BigEndian.Uint16(b)

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
			dns.Questions = binary.BigEndian.Uint16(b)

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
			dns.AnswerRRs = binary.BigEndian.Uint16(b)

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
			dns.AdditionalRRs = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddInputField("Queries Domain", DEFAULT_DNS_QUERIES_DOMAIN, 64, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 64 {
				dns.Domain(textToCheck)
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
			dns.Queries.Typ = binary.BigEndian.Uint16(b)

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
			dns.Queries.Class = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			udp.Len()
			udp.Data = dns.Bytes()
			ipv4.Data = udp.Bytes()
			ipv4.CalculateTotalLength()
			// 前回Send分が残ってると計算誤るため
			ipv4.HeaderChecksum = 0x0
			ipv4.CalculateChecksum()
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
				Data:   ipv4.Bytes(),
			}
			if err := sendFn(ethernetFrame); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Under layer", func() {
			t.pages.SwitchToPage("IPv4")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return dnsForm
}
