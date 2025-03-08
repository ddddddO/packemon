package tui

import (
	"github.com/rivo/tview"
)

func (t *tui) tlsv1_3Form() *tview.Form {
	tlsv1_3Form := tview.NewForm().
		AddTextView("TLSv1.3", "TLS v1.3 has been selected;\nafter TLS v1.3 handshake,\nthe request is made with upper layer encrypted.", 60, 4, true, false).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return tlsv1_3Form
}
