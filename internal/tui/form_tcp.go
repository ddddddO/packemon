package tui

import (
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) tcpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, tcp *packemon.TCP) *tview.Form {
	tcpForm := tview.NewForm().
		AddTextView("TCP", "This section generates the TCP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Source Port", DEFAULT_TCP_PORT_SOURCE, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				tcp.SrcPort = n
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
				tcp.DstPort = n
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
			tcp.Sequence = binary.BigEndian.Uint32(b)

			return true
		}, nil).
		AddInputField("Flags", DEFAULT_TCP_FLAGS, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < 5 {
				return true
			} else if len(textToCheck) > 5 {
				return false
			}

			b, err := packemon.StrHexToBytes2(textToCheck)
			if err != nil {
				return false
			}
			tcp.Flags = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			tcp.Data = []byte{} // 前回分の TCP より上のデータをクリア
			tcp.CalculateChecksum(ipv4)
			ipv4.Data = tcp.Bytes()
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
		// TODO: 上のレイヤーどれにするか選択肢あったほうが？
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return tcpForm
}
