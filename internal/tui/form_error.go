package tui

import (
	"fmt"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// TODO: addErrPageForMonitor みたいに、キー押下で正常なページに遷移させるといいかも
//
//	t.pages.SwitchToPage("Ethernet") みたいにして、見えてたページに戻すように
func (t *tui) addErrPage(err error) {
	t.pages.AddPage("ERROR", t.errView(err), true, true)
}

func (t *tui) addErrPageForMonitor(err error) {
	e := t.errView(err)
	e.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape || key == tcell.KeyEnter {
			t.grid.Clear()
			t.pages.SwitchToPage("history")
		}
	})

	t.pages.AddPage("ERROR", e, true, true)
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
