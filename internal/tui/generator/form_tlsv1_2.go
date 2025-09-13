package generator

import (
	"github.com/rivo/tview"
)

var doCustomOfTLSv12 bool

func (g *generator) tlsv1_2Form() *tview.Form {
	tlsv1_2Form := tview.NewForm().
		AddTextView("TLSv1.2", "TLS v1.2 has been selected;\nafter TLS v1.2 handshake,\nthe request is made with upper layer encrypted.", 60, 4, true, false).
		AddCheckbox("Do experimental implementation ?", doCustomOfTLSv12, func(checked bool) {
			doCustomOfTLSv12 = checked
		}).
		AddTextView("!!caution!!", "Experimental implementation may not work properly.", 60, 4, true, false).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return tlsv1_2Form
}
