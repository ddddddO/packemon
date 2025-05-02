package tui

import (
	"fmt"

	"github.com/rivo/tview"
)

func ErrView(err error, app *tview.Application) *tview.TextView {
	textview := tview.NewTextView().
		SetDynamicColors(true).
		SetRegions(true).
		SetChangedFunc(func() {
			app.Draw()
		})
	textview.SetBorder(true).SetTitle("Error")
	fmt.Fprintf(textview, " Error detail:\n %s\n", err)

	return textview
}
