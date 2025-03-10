package tui

import (
	"context"
	"sync"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type tui struct {
	networkInterface *packemon.NetworkInterface

	app *tview.Application

	table         *tview.Table
	storedPackets sync.Map

	grid  *tview.Grid
	pages *tview.Pages
	list  *tview.List

	sender *sender
}

func NewTUI(networkInterface *packemon.NetworkInterface, wantSend bool) *tui {
	if wantSend {
		return newGenerator(networkInterface)
	}
	return newMonitor(networkInterface)
}

func newGenerator(networkInterface *packemon.NetworkInterface) *tui {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Generator> ").SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &tui{
		networkInterface: networkInterface,

		app:   tview.NewApplication(),
		grid:  grid,
		pages: pages,
		list:  list,
	}
}

func newMonitor(networkInterface *packemon.NetworkInterface) *tui {
	pages := tview.NewPages()
	table := NewPacketsHistoryTable()
	pages.AddPage("history", table, true, true)
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Monitor> ").SetBorder(true)

	return &tui{
		networkInterface: networkInterface,

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
			t.table.SetSelectable(true, false)
		}
	}).SetSelectedStyle(tcell.Style{}.Background(tcell.ColorRed)).SetSelectedFunc(func(row int, column int) {
		for i := 0; i < t.table.GetColumnCount(); i++ {
			t.table.GetCell(row, i).SetBackgroundColor(tcell.ColorGray)
		}

		if p, ok := t.storedPackets.Load(uint64(t.table.GetRowCount() - row - 1)); ok {
			t.updateView(p.(*packemon.Passive))
		}
	})

	go t.updateTable(passiveCh, columns)
	return t.app.SetRoot(t.pages, true).EnableMouse(true).Run()
}
