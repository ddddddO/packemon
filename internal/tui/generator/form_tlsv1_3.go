package generator

import (
	"github.com/rivo/tview"
)

func (g *generator) tlsv1_3Form() *tview.Form {
	tlsv1_3Form := tview.NewForm().
		AddTextView("!!caution!!", "Experimental implementation and may not work properly.", 60, 2, true, false).
		AddTextView("TLSv1.3", "TLS v1.3 has been selected;\nafter TLS v1.3 handshake,\nthe request is made with upper layer encrypted.", 60, 4, true, false).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return tlsv1_3Form
}
