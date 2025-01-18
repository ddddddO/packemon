package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type HTTP struct {
	*packemon.HTTP
}

func (*HTTP) rows() int {
	return 8
}

func (*HTTP) columns() int {
	return 30
}

func (h *HTTP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" HTTP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Method"))
	table.SetCell(0, 1, tableCellContent("%s", h.Method))

	table.SetCell(1, 0, tableCellTitle("Uri"))
	table.SetCell(1, 1, tableCellContent("%s", h.Uri))

	table.SetCell(2, 0, tableCellTitle("Version"))
	table.SetCell(2, 1, tableCellContent("%s", h.Version))

	table.SetCell(3, 0, tableCellTitle("Host"))
	table.SetCell(3, 1, tableCellContent("%s", h.Host))

	return table
}
