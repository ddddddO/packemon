package tui

import (
	"context"
	"sync"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type tui struct {
	app *tview.Application

	table         *tview.Table
	storedPackets sync.Map

	grid  *tview.Grid
	pages *tview.Pages
	list  *tview.List
}

func NewTUI(wantSend bool) *tui {
	if wantSend {
		return newGenerator()
	}
	return newMonitor()
}

func newGenerator() *tui {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Generator> ").SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &tui{
		app:   tview.NewApplication(),
		grid:  grid,
		pages: pages,
		list:  list,
	}
}

func newMonitor() *tui {
	pages := tview.NewPages()
	table := NewPacketsHistoryTable()
	pages.AddPage("history", table, true, true)
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Monitor> ").SetBorder(true)

	return &tui{
		app:           tview.NewApplication(),
		table:         table,
		storedPackets: sync.Map{},
		grid:          grid,
		pages:         pages,
	}
}

func (t *tui) Generator(ctx context.Context, sendFn func(*packemon.EthernetFrame) error) error {
	if err := t.form(ctx, sendFn); err != nil {
		return err
	}
	return t.app.SetRoot(t.grid, true).EnableMouse(true).SetFocus(t.grid).Run()
}

func (t *tui) Monitor(passiveCh <-chan *packemon.Passive, columns string) error {
	t.table.Select(0, 0).SetFixed(1, 1).SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			t.table.SetSelectable(false, false)
		}
		if key == tcell.KeyEnter {
			t.table.SetSelectable(true, true)
		}
	}).SetSelectedFunc(func(row int, column int) {
		t.table.GetCell(row, column).SetTextColor(tcell.ColorRed)

		if p, ok := t.storedPackets.Load(uint64(t.table.GetRowCount() - row - 1)); ok {
			t.updateView(p.(*packemon.Passive))
		}
	})

	go t.updateTable(passiveCh, columns)
	return t.app.SetRoot(t.pages, true).Run()
}
