package tui

import (
	"fmt"

	"github.com/rivo/tview"
)

func (t *tui) addErrPage(err error) {
	t.pages.AddPage("ERROR", t.errView(err), true, true)
}

func (t *tui) errView(err error) *tview.TextView {
	textview := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			t.app.Draw()
		})
	textview.SetBorder(true).SetTitle("Error")
	fmt.Fprintf(textview, " Error detail:\n %s\n", err)

	return textview
}
