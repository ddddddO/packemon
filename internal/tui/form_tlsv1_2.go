package tui

import (
	"github.com/rivo/tview"
)

// TODO: いつか
func (t *tui) tlsv1_2Form() *tview.Form {
	tlsv1_2Form := tview.NewForm().
		AddTextView("!!UNDER THE DEVELOPMENT!!", "noop", 60, 4, true, false).
		AddButton("Quit", func() {
			t.app.Stop()
		})

	return tlsv1_2Form
}
