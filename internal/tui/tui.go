package tui

import (
	"context"
	"sync"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type TUI interface {
	Run(context.Context) error
}

type generator struct {
	networkInterface *packemon.NetworkInterface
	sendFn           func(*packemon.EthernetFrame) error

	app *tview.Application

	grid   *tview.Grid
	pages  *tview.Pages
	list   *tview.List
	sender *sender
}

type monitor struct {
	networkInterface *packemon.NetworkInterface
	passiveCh        <-chan *packemon.Passive
	columns          string

	app *tview.Application

	table         *tview.Table
	storedPackets sync.Map

	grid  *tview.Grid
	pages *tview.Pages
}

func NewGenerator(networkInterface *packemon.NetworkInterface, sendFn func(*packemon.EthernetFrame) error) *generator {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Generator> ").SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &generator{
		networkInterface: networkInterface,
		sendFn:           sendFn, // TODO: networkInterface そのまま使う

		app:   tview.NewApplication(),
		grid:  grid,
		pages: pages,
		list:  list,
	}
}

func (g *generator) Run(ctx context.Context) error {
	if err := g.form(ctx, g.sendFn); err != nil {
		return err
	}
	return g.app.SetRoot(g.grid, true).EnableMouse(true).SetFocus(g.grid).Run()
}

func (g *generator) addErrPage(err error) {
	g.pages.AddPage("ERROR", errView(err, g.app), true, true)
}

func NewMonitor(networkInterface *packemon.NetworkInterface, passiveCh <-chan *packemon.Passive, columns string) *monitor {
	pages := tview.NewPages()
	table := NewPacketsHistoryTable()
	pages.AddPage("history", table, true, true)
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(" Packemon <Monitor> ").SetBorder(true)

	return &monitor{
		networkInterface: networkInterface,
		passiveCh:        passiveCh,
		columns:          columns,

		app:           tview.NewApplication(),
		table:         table,
		storedPackets: sync.Map{},
		grid:          grid,
		pages:         pages,
	}
}

func (m *monitor) Run(ctx context.Context) error {
	go m.networkInterface.Recieve(ctx)

	m.table.Select(0, 0).SetFixed(1, 1).SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			m.table.SetSelectable(false, false)
		}
		if key == tcell.KeyEnter {
			m.table.SetSelectable(true, false)
		}
	}).SetSelectedStyle(tcell.Style{}.Background(tcell.ColorRed)).SetSelectedFunc(func(row int, column int) {
		for i := 0; i < m.table.GetColumnCount(); i++ {
			m.table.GetCell(row, i).SetBackgroundColor(tcell.ColorGray)
		}

		if p, ok := m.storedPackets.Load(uint64(m.table.GetRowCount() - row - 1)); ok {
			m.updateView(p.(*packemon.Passive))
		}
	})

	go m.updateTable(m.passiveCh, m.columns)
	return m.app.SetRoot(m.pages, true).EnableMouse(true).Run()
}

func (m *monitor) addErrPage(err error) {
	e := errView(err, m.app)
	e.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape || key == tcell.KeyEnter {
			m.grid.Clear()
			m.pages.SwitchToPage("history")
		}
	})

	m.pages.AddPage("ERROR", e, true, true)
}
