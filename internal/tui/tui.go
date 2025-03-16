package tui

import (
	"context"
	"slices"
	"strconv"
	"sync"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

const (
	TITLE_GENERATOR = " Packemon <Generator> "
	TITLE_MONITOR   = " Packemon <Monitor> "
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

	grid        *tview.Grid
	filterInput *tview.Grid
	filter      *filter
	pages       *tview.Pages
}

func NewGenerator(networkInterface *packemon.NetworkInterface) *generator {
	pages := tview.NewPages()
	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(TITLE_GENERATOR).SetBorder(true)
	list := tview.NewList()
	list.SetTitle("Protocols").SetBorder(true)

	return &generator{
		networkInterface: networkInterface,
		sendFn:           networkInterface.Send,

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

func NewMonitor(networkInterface *packemon.NetworkInterface, columns string) *monitor {
	pages := tview.NewPages()
	table := NewPacketsHistoryTable()
	pages.AddPage("history", table, true, true)

	filterInput := tview.NewGrid()
	filterInput.Box.SetBorder(true)

	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(TITLE_MONITOR).SetBorder(true)
	// grid.AddItem(filterInput, 0, 0, 1, 1, 0, 0, false)
	grid.AddItem(pages, 1, 0, 9, 1, 1, 1, true)

	return &monitor{
		networkInterface: networkInterface,
		passiveCh:        networkInterface.PassiveCh,
		columns:          columns,

		app:           tview.NewApplication(),
		table:         table,
		storedPackets: sync.Map{},
		grid:          grid,
		filterInput:   filterInput,
		filter:        newFilter(),
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
		for i := range m.table.GetColumnCount() {
			m.table.GetCell(row, i).SetBackgroundColor(tcell.ColorGray)
		}

		selectedCell := m.table.GetCell(row, 0)
		id, err := strconv.ParseUint(selectedCell.Text, 10, 64)
		if err != nil {
			return
		}
		if p, ok := m.storedPackets.Load(id); ok {
			m.updateView(p.(*packemon.Passive))
		}
	})

	filterInput := tview.NewInputField().SetLabel("Filter")
	filterInput.SetBorderPadding(1, 1, 1, 0)
	filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter {
			m.filter.value = filterInput.GetText()
			m.updateFilteredTable()
		}
		return event
	})
	filterOKButton := tview.NewButton("ok").SetSelectedFunc(func() {
		m.filter.value = filterInput.GetText()
		m.updateFilteredTable()
	})
	filterClearButton := tview.NewButton("clear").SetSelectedFunc(func() {
		filterInput.SetText("")
		m.filter.value = ""
		m.updateFilteredTable()
	})
	filterClearButton.SetStyle(tcell.Style{}.Foreground(tcell.ColorWhiteSmoke).Background(tcell.ColorGray))
	filterLayout := tview.NewGrid().
		AddItem(filterInput, 0, 0, 1, 4, 0, 0, true).
		AddItem(filterOKButton, 0, 5, 1, 1, 0, 0, false).
		AddItem(filterClearButton, 0, 6, 1, 1, 0, 0, false)
	filterLayout.Box.SetBorder(true)
	m.filterInput = filterLayout
	m.grid.AddItem(m.filterInput, 0, 0, 1, 1, 0, 0, false)

	go m.updateTable()
	return m.app.SetRoot(m.grid, true).EnableMouse(true).SetFocus(m.pages).Run()
}

func (m *monitor) updateFilteredTable() {
	// 一回クリア
	m.table.Clear()

	sortedIDs := []uint64{}
	m.storedPackets.Range(func(key any, value any) bool {
		sortedIDs = append(sortedIDs, key.(uint64))
		return true
	})
	// TODO: id は 0~ で歯抜けることはない想定なので、sort せず最大のid保持しておいてforで、Loadでid指定して取り出すのもいいかも
	slices.Sort(sortedIDs)

	// filter 処理(なお、filter文字列が空なら全部表示)
	for _, id := range sortedIDs {
		value, ok := m.storedPackets.Load(id)
		if !ok {
			continue
		}
		passive := value.(*packemon.Passive)
		m.filterAndInsertToTable(passive, id)
	}
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
