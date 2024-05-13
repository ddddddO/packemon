package tui

import (
	"fmt"

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

	table.SetCell(0, 0, tview.NewTableCell(padding("Method")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf(h.Method))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Uri")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf(h.Uri))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Version")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf(h.Version))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Host")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf(h.Host))))

	return table
}
