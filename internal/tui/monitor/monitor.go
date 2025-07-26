package monitor

import (
	"context"
	"strconv"
	"sync"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type monitor struct {
	networkInterface *packemon.NetworkInterface
	passiveCh        <-chan *packemon.Passive
	columns          string

	app *tview.Application

	table         *tview.Table
	storedPackets sync.Map
	storedMaxID   *storedMaxID
	limit         int

	grid        *tview.Grid
	filterInput *tview.Grid
	filter      *filter
	pages       *tview.Pages
}

type storedMaxID struct {
	value uint64
	mu    sync.RWMutex
}

func (m *storedMaxID) get() uint64 {
	defer m.mu.RUnlock()
	m.mu.RLock()
	return m.value
}

func (m *storedMaxID) set(currentID uint64) {
	defer m.mu.Unlock()
	m.mu.Lock()
	if currentID > m.value {
		m.value = currentID
	}
}

func New(networkInterface *packemon.NetworkInterface, columns string, limit int) *monitor {
	pages := tview.NewPages()
	table := NewPacketsHistoryTable()
	pages.AddPage("history", table, true, true)

	filterInput := tview.NewGrid()
	filterInput.Box.SetBorder(true)

	grid := tview.NewGrid()
	grid.SetRows(1, 0, -10, 1)
	grid.Box = tview.NewBox().SetTitle(tui.TITLE_MONITOR).SetBorder(true)
	grid.AddItem(filterInput, 0, 0, -1, 1, -1, 1, false)
	grid.AddItem(pages, 1, 0, 2, 1, 5, 1, true)

	footer := tview.NewTextView().
		SetText("Focus on packet list and press Enter to selectable mode | Press Esc to return").
		SetTextAlign(tview.AlignLeft)
	footer.SetBorderPadding(0, 0, 1, 1)

	grid.AddItem(footer, 3, 0, 1, 1, 1, 1, false)

	return &monitor{
		networkInterface: networkInterface,
		passiveCh:        networkInterface.PassiveCh,
		columns:          columns,

		app:           tview.NewApplication(),
		table:         table,
		storedPackets: sync.Map{},
		storedMaxID:   &storedMaxID{},
		limit:         limit,
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
			m.table.Select(0, 0)
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

	filterInput := tview.NewInputField().SetLabel("Filter ")
	filterInput.SetBorderPadding(0, 0, 1, 0)
	filterInput.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		if event.Key() == tcell.KeyEnter {
			m.filter.value = filterInput.GetText()
			m.reCreateTable()
		}
		return event
	})
	filterOKButton := tview.NewButton("ok").SetSelectedFunc(func() {
		m.filter.value = filterInput.GetText()
		m.reCreateTable()
	})
	filterClearButton := tview.NewButton("clear").SetSelectedFunc(func() {
		filterInput.SetText("")
		m.filter.value = ""
		m.reCreateTable()
	})

	filterClearButton.SetStyle(tcell.Style{}.Foreground(tcell.ColorWhiteSmoke).Background(tcell.ColorGray))
	filterLayout := tview.NewGrid().
		AddItem(filterInput, 0, 0, 1, 4, 0, 0, true).
		AddItem(filterOKButton, 0, 5, 1, 1, 0, 0, false).
		AddItem(filterClearButton, 0, 6, 1, 1, 0, 0, false)
	filterLayout.SetRows(1)
	// filterLayout.Box.SetBorder(true)
	m.filterInput = filterLayout
	m.grid.AddItem(m.filterInput, 0, 0, 1, 1, 0, 0, false)

	go m.updateTable()
	return m.app.SetRoot(m.grid, true).EnableMouse(true).SetFocus(m.pages).Run()
}

func (m *monitor) addErrPage(err error) {
	e := tui.ErrView(err, m.app)
	e.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape || key == tcell.KeyEnter {
			m.grid.Clear()
			m.pages.SwitchToPage("history")
		}
	})

	m.pages.AddPage("ERROR", e, true, true)
}
