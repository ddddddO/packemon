package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type EthernetFrame struct {
	*packemon.EthernetFrame
}

func (*EthernetFrame) rows() int {
	return 7
}

func (*EthernetFrame) columns() int {
	return 30
}

func (ef *EthernetFrame) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Destination MAC Addr"))
	table.SetCell(0, 1, tableCellContent("%x", ef.Header.Dst))

	table.SetCell(1, 0, tableCellTitle("Source MAC Addr"))
	table.SetCell(1, 1, tableCellContent("%x", ef.Header.Src))

	table.SetCell(2, 0, tableCellTitle("Type"))
	table.SetCell(2, 1, tableCellContent("%x", ef.Header.Typ))

	return table
}
