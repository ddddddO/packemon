package generator

import (
	"github.com/rivo/tview"
)

func (g *generator) quicForm() *tview.Form {
	quicForm := tview.NewForm().
		AddTextView("QUIC", "QUIC has been selected;\nRequest is made with upper layer encrypted.", 60, 4, true, false).
		AddInputField("TLS: ServerName", DEFAULT_QUIC_TLS_SERVER_NAME, 50, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) <= 50 {
				g.sender.packets.quic.TLSConfig.ServerName = textToCheck
				return true
			}
			return false
		}, nil).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return quicForm
}
