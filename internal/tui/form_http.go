package tui

import (
	"bytes"
	"encoding/binary"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

func (t *tui) httpForm(sendFn func(*packemon.EthernetFrame) error, ethernetHeader *packemon.EthernetHeader, ipv4 *packemon.IPv4, tcp *packemon.TCP, http *packemon.HTTP) *tview.Form {
	do3wayHandshake := false

	httpForm := tview.NewForm().
		AddTextView("HTTP", "This section generates the HTTP.\nIt is still under development.", 60, 4, true, false).
		AddCheckbox("Do 3way handshake ?", do3wayHandshake, func(checked bool) {
			do3wayHandshake = checked
		}).
		AddTextView("", "When 3-way handshake for TCP is enabled, only \n\n  - HTTP section\n  - TCP Destination Port\n  - IPv4 Destination IP Addr\n\nare reflected as input.", 60, 7, true, true).
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
				if err := packemon.EstablishConnectionAndSendPayload(
					DEFAULT_NW_INTERFACE,
					dstIPAddr,
					tcp.DstPort,
					// []byte{0xc0, 0xa8, 0x0a, 0x6e},
					// 0x0050,
					http.Bytes(),
				); err != nil {
					t.addErrPage(err)
				}
				return
			}

			tcp.Data = http.Bytes()
			tcp.Checksum = func() uint16 {
				pseudoTCPHeader := func() []byte {
					buf := &bytes.Buffer{}
					packemon.WriteUint32(buf, ipv4.SrcAddr)
					packemon.WriteUint32(buf, ipv4.DstAddr)
					padding := byte(0x00)
					buf.WriteByte(padding)
					buf.WriteByte(ipv4.Protocol)
					packemon.WriteUint16(buf, uint16(len(tcp.Bytes())))
					return buf.Bytes()
				}()

				forTCPChecksum := &bytes.Buffer{}
				forTCPChecksum.Write(pseudoTCPHeader)
				forTCPChecksum.Write(tcp.Bytes())
				return binary.BigEndian.Uint16(tcp.CheckSum(forTCPChecksum.Bytes()))
			}()

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
