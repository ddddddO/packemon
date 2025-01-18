package tui

import (
	"github.com/ddddddO/packemon"
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

	table.SetCell(0, 0, tableCellTitle("Type"))
	table.SetCell(0, 1, tableCellContent("%x", i.Typ))

	table.SetCell(1, 0, tableCellTitle("Code"))
	table.SetCell(1, 1, tableCellContent("%x", i.Code))

	table.SetCell(2, 0, tableCellTitle("Checksum"))
	table.SetCell(2, 1, tableCellContent("%x", i.Checksum))

	table.SetCell(3, 0, tableCellTitle("Identifier"))
	table.SetCell(3, 1, tableCellContent("%d", i.Identifier))

	table.SetCell(4, 0, tableCellTitle("Sequence"))
	table.SetCell(4, 1, tableCellContent("%x", i.Sequence))

	viewHexadecimalDumpByProtocol(table, 5, "Data", i.Data)

	return table
}
