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

	// TODO: Monitor/Generator のどちらから呼ばれたかで、Enter/Escape 押下で前の画面に戻るようにしたい
	// textview.SetDoneFunc(func(key tcell.Key) {
	// 	if key == tcell.KeyEscape || key == tcell.KeyEnter {

	// 	}
	// })
	textview.SetBorder(true).SetTitle("Error")
	fmt.Fprintf(textview, " Error detail:\n %s\n", err)

	return textview
}
