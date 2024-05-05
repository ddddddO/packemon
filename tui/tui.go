package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type tui struct {
	app   *tview.Application
	grid  *tview.Grid
	pages *tview.Pages
}

func NewTUI(wantSend bool) *tui {
	app := tview.NewApplication()

	if wantSend {
		pages := tview.NewPages()
		pages.Box = tview.NewBox().SetTitle(" Packemon [Make & Send packet] ").SetBorder(true)
		return &tui{
			app:   app,
			pages: pages,
		}
	}

	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon ")
	return &tui{
		app:  tview.NewApplication(),
		grid: grid,
	}
}

func (t *tui) Monitor(passiveCh chan packemon.Passive) error {
	go t.updateView(passiveCh)
	// go t.netIF.Recieve(t.viewersCh)

	return t.app.SetRoot(t.grid, true).Run()
}

func (t *tui) Generator() error {
	// if err := t.form(t.netIF.SendForForm); err != nil {
	// 	return err
	// }
	return t.app.SetRoot(t.pages, true).EnableMouse(true).Run()
}
