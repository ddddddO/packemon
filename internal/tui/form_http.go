package tui

import (
	"context"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) httpForm(ctx context.Context, sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, tcp *packemon.TCP, http *packemon.HTTP) *tview.Form {
	do3wayHandshake := false

	httpForm := tview.NewForm().
		AddTextView("HTTP", "This section generates the HTTP.\nIt is still under development.", 60, 4, true, false).
		AddCheckbox("Do TCP 3way handshake ?", do3wayHandshake, func(checked bool) {
			do3wayHandshake = checked
		}).
		AddInputField("Method", DEFAULT_HTTP_METHOD, 10, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				http.Method = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Uri", DEFAULT_HTTP_URI, 30, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 30 {
				http.Uri = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Version", DEFAULT_HTTP_VERSION, 10, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				http.Version = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Host", DEFAULT_HTTP_HOST, 50, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 50 {
				http.Host = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("UserAgent", DEFAULT_HTTP_USER_AGENT, 20, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				http.UserAgent = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Accept", DEFAULT_HTTP_ACCEPT, 30, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 30 {
				http.Accept = textToCheck
				return true
			}
			return false
		}, nil).
		AddButton("List", func() {
			t.app.SetFocus(t.list)
		}).
		AddButton("Send!", func() {
			if do3wayHandshake {
				dstIPAddr := make([]byte, 4)
				binary.BigEndian.PutUint32(dstIPAddr, ipv4.DstAddr)
				// if err := packemon.EstablishConnectionAndSendPayload(
				// 	DEFAULT_NW_INTERFACE,
				// 	dstIPAddr,
				// 	tcp.DstPort,
				// 	// []byte{0xc0, 0xa8, 0x0a, 0x6e},
				// 	// 0x0050,
				// 	http.Bytes(),
				// ); err != nil {
				// 	t.addErrPage(err)
				// }

				go func() {
					if err := packemon.EstablishConnectionAndSendPayloadXxx(
						ctx,
						DEFAULT_NW_INTERFACE,
						ethernetHeader,
						ipv4,
						tcp,
						http,
					); err != nil {
						t.addErrPage(err)
					}
				}()

				return
			}

			tcp.Data = http.Bytes()
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
			t.pages.SwitchToPage("TCP")
		}).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return httpForm
}
