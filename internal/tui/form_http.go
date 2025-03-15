package tui

import (
	"context"

	"github.com/rivo/tview"
)

var do3wayHandshakeForHTTP = false

func (g *generator) httpForm(ctx context.Context) *tview.Form {
	httpForm := tview.NewForm().
		AddTextView("HTTP", "This section generates the HTTP.\nIt is still under development.", 60, 4, true, false).
		AddCheckbox("Do TCP 3way handshake ?", do3wayHandshakeForHTTP, func(checked bool) {
			do3wayHandshakeForHTTP = checked
		}).
		AddInputField("Method", DEFAULT_HTTP_METHOD, 10, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				g.sender.packets.http.Method = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Uri", DEFAULT_HTTP_URI, 30, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 30 {
				g.sender.packets.http.Uri = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Version", DEFAULT_HTTP_VERSION, 10, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				g.sender.packets.http.Version = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Host", DEFAULT_HTTP_HOST, 50, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 50 {
				g.sender.packets.http.Host = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("UserAgent", DEFAULT_HTTP_USER_AGENT, 20, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 10 {
				g.sender.packets.http.UserAgent = textToCheck
				return true
			}
			return false
		}, nil).
		AddInputField("Accept", DEFAULT_HTTP_ACCEPT, 30, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 30 {
				g.sender.packets.http.Accept = textToCheck
				return true
			}
			return false
		}, nil).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer7(ctx); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return httpForm
}
