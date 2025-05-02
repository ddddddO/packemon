package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type ICMP struct {
	*packemon.ICMP
}

func (*ICMP) rows() int {
	return 16
}

func (*ICMP) columns() int {
	return 30
}

func (i *ICMP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" ICMP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Type"))
	table.SetCell(0, 1, tui.TableCellContent("%x", i.Typ))

	table.SetCell(1, 0, tui.TableCellTitle("Code"))
	table.SetCell(1, 1, tui.TableCellContent("%x", i.Code))

	table.SetCell(2, 0, tui.TableCellTitle("Checksum"))
	table.SetCell(2, 1, tui.TableCellContent("%x", i.Checksum))

	table.SetCell(3, 0, tui.TableCellTitle("Identifier"))
	table.SetCell(3, 1, tui.TableCellContent("%d", i.Identifier))

	table.SetCell(4, 0, tui.TableCellTitle("Sequence"))
	table.SetCell(4, 1, tui.TableCellContent("%x", i.Sequence))

	viewHexadecimalDump(table, 5, "Data", i.Data)

	return table
}
