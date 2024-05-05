package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type tui struct {
	app   *tview.Application
	grid  *tview.Grid
	pages *tview.Pages
	list  *tview.List
}

func NewTUI(wantSend bool) *tui {
	app := tview.NewApplication()

	if wantSend {
		pages := tview.NewPages()

		list := tview.NewList()
		list.SetTitle("List of protocols").SetBorder(true)

		grid := tview.NewGrid()
		grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon <Generator> ")

		return &tui{
			app:   app,
			grid:  grid,
			pages: pages,
			list:  list,
		}
	}

	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon <Monitor> ")
	return &tui{
		app:  tview.NewApplication(),
		grid: grid,
	}
}

func (t *tui) Monitor(passiveCh chan packemon.Passive) error {
	go t.updateView(passiveCh)
	return t.app.SetRoot(t.grid, true).Run()
}

func (t *tui) Generator(sendFn func(*packemon.EthernetFrame) error) error {
	if err := t.form(sendFn); err != nil {
		return err
	}
	return t.app.SetRoot(t.grid, true).EnableMouse(true).SetFocus(t.grid).Run()
}
