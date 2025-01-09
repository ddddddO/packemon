package tui

import (
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcUDPLength = false

func (t *tui) udpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, udp *packemon.UDP) *tview.Form {
	udpForm := tview.NewForm().
		AddTextView("UDP", "This section generates the UDP.\nIt is still under development.", 60, 4, true, false).
		AddInputField("Source Port", DEFAULT_UDP_PORT_SOURCE, 5, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 5 {
				n, err := packemon.StrIntToUint16(textToCheck)
				if err != nil {
					return false
				}
				udp.SrcPort = n
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
				udp.DstPort = n
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
			udp.Length = binary.BigEndian.Uint16(b)

			return true
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			udp.Data = []byte{} // 前回分の UDP より上のデータをクリア
			if checkedCalcUDPLength {
				udp.Len()
			}
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
		// TODO: 上のレイヤーどれにするか選択肢あったほうが？
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return udpForm
}
