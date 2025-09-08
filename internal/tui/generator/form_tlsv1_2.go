package generator

import (
	"github.com/rivo/tview"
)

func (g *generator) tlsv1_2Form() *tview.Form {
	tlsv1_2Form := tview.NewForm().
		AddTextView("!!caution!!", "Experimental implementation and may not work properly.", 60, 2, true, false).
		AddTextView("TLSv1.2", "TLS v1.2 has been selected;\nafter TLS v1.2 handshake,\nthe request is made with upper layer encrypted.", 60, 4, true, false).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return tlsv1_2Form
}
