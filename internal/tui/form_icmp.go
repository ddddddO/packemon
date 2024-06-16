package tui

import (
	"encoding/binary"
	"time"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) icmpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, icmp *packemon.ICMP) *tview.Form {
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
			icmp.Typ = uint8(b)

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
			icmp.Code = uint8(b)

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
			icmp.Identifier = binary.BigEndian.Uint16(b)

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
			icmp.Sequence = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			// TODO: timestamp関数化
			icmp.Data = func() []byte {
				now := time.Now().Unix()
				b := make([]byte, 4)
				binary.LittleEndian.PutUint32(b, uint32(now))
				return binary.LittleEndian.AppendUint32(b, 0x00000000)
			}()
			// 前回Send分が残ってると計算誤るため
			icmp.Checksum = 0x0
			icmp.Checksum = func() uint16 {
				b := make([]byte, 2)
				binary.LittleEndian.PutUint16(b, icmp.CalculateChecksum())
				return binary.BigEndian.Uint16(b)
			}()
			ipv4.Data = icmp.Bytes()
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

	return icmpForm
}
