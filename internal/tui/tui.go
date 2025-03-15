package tui

import (
	"context"
	"sort"
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
	filter      *tview.Form
	filterValue string
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

	filter := tview.NewForm()
	// AddInputField("Filter", "", 0, func (textToCheck string, lastChar rune) bool {
	// 	filterText = textToCheck
	// 	return true
	// }, nil).
	// AddButton("ok", func ()  {

	// })
	filter.Box.SetBorder(true)
	filter.SetHorizontal(true)
	// filter := tview.NewInputField()
	// filter.Box = tview.NewBox().SetTitle("Filter").SetBorder(true)

	grid := tview.NewGrid()
	grid.Box = tview.NewBox().SetTitle(TITLE_MONITOR).SetBorder(true)
	grid.AddItem(filter, 0, 0, 1, 1, 0, 0, false)
	grid.AddItem(pages, 1, 0, 9, 1, 1, 1, true)

	return &monitor{
		networkInterface: networkInterface,
		passiveCh:        networkInterface.PassiveCh,
		columns:          columns,

		app:           tview.NewApplication(),
		table:         table,
		storedPackets: sync.Map{},
		grid:          grid,
		filter:        filter,
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

		selectedCell := m.table.GetCell(row, 0)
		id, err := strconv.ParseUint(selectedCell.Text, 10, 64)
		if err != nil {
			return
		}
		if p, ok := m.storedPackets.Load(id); ok {
			m.updateView(p.(*packemon.Passive))
		}
	})

	tmpFilterValue := ""
	m.filter.
		AddInputField("Filter", "", 50, func(textToCheck string, lastChar rune) bool {
			return true
		}, func(text string) {
			// ここで、m.filterValue に格納すると、ボタン押さなくても後続の受信パケットでfilter文字列によるフィルターが実行されるため
			tmpFilterValue = text
		}).
		AddButton("ok", func() {
			m.filterValue = tmpFilterValue
			// 一回クリア
			m.table.Clear()

			sortedKeys := []uint64{}
			m.storedPackets.Range(func(key any, value any) bool {
				sortedKeys = append(sortedKeys, key.(uint64))
				return true
			})
			// TODO: id は 0~ で歯抜けることはない想定なので、sort せず最大のid保持しておいてforで、Loadでid指定して取り出すのもいいかも
			sort.Slice(sortedKeys, func(i int, j int) bool {
				return sortedKeys[i] < sortedKeys[j]
			})

			// filter 処理(なお、filter文字列が空なら全部表示)
			for _, id := range sortedKeys {
				value, ok := m.storedPackets.Load(id)
				if !ok {
					continue
				}
				passive := value.(*packemon.Passive)
				m.doFilter(passive, id)
			}
		})

	go m.updateTable(m.passiveCh, m.columns)
	return m.app.SetRoot(m.grid, true).EnableMouse(true).SetFocus(m.pages).Run()
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
