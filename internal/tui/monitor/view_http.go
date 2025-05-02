package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
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

	table.SetCell(0, 0, tui.TableCellTitle("Method"))
	table.SetCell(0, 1, tui.TableCellContent("%s", h.Method))

	table.SetCell(1, 0, tui.TableCellTitle("Uri"))
	table.SetCell(1, 1, tui.TableCellContent("%s", h.Uri))

	table.SetCell(2, 0, tui.TableCellTitle("Version"))
	table.SetCell(2, 1, tui.TableCellContent("%s", h.Version))

	table.SetCell(3, 0, tui.TableCellTitle("Host"))
	table.SetCell(3, 1, tui.TableCellContent("%s", h.Host))

	return table
}
