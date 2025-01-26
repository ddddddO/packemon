package tui

import (
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) tcpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, ipv6 *packemon.IPv6, tcp *packemon.TCP) *tview.Form {
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
			tcp.Flags = b

			return true
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			tcp.Checksum = 0x0000
			tcp.Data = []byte{} // 前回分の TCP より上のデータをクリア
			ethernetFrame := &packemon.EthernetFrame{
				Header: ethernetHeader,
			}

			if underIPv6 {
				tcp.CalculateChecksumForIPv6(ipv6)
				ipv6.Data = tcp.Bytes()
				ipv6.PayloadLength = uint16(len(ipv6.Data))
				ethernetFrame.Data = ipv6.Bytes()
			} else {
				tcp.CalculateChecksum(ipv4)
				ipv4.Data = tcp.Bytes()
				ipv4.CalculateTotalLength()
				// 前回Send分が残ってると計算誤るため
				ipv4.HeaderChecksum = 0x0
				ipv4.CalculateChecksum()
				ethernetFrame.Data = ipv4.Bytes()
			}

			if err := sendFn(ethernetFrame); err != nil {
				t.addErrPage(err)
			}
		}).
		AddButton("Under layer", func() {
			if underIPv6 {
				t.pages.SwitchToPage("IPv6")
			} else {
				t.pages.SwitchToPage("IPv4")
			}
		}).
		// TODO: 上のレイヤーどれにするか選択肢あったほうが？
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return tcpForm
}
