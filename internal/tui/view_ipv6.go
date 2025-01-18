package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type IPv6 struct {
	*packemon.IPv6
}

func (*IPv6) rows() int {
	return 16
}

func (*IPv6) columns() int {
	return 30
}

func (i *IPv6) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" IPv6 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Version"))
	table.SetCell(0, 1, tableCellContent("%x", i.Version))

	table.SetCell(1, 0, tableCellTitle("Traffic Class"))
	table.SetCell(1, 1, tableCellContent("%x", i.TrafficClass))

	table.SetCell(2, 0, tableCellTitle("Flow Label"))
	table.SetCell(2, 1, tableCellContent("<under development!>"))

	table.SetCell(3, 0, tableCellTitle("Payload Length"))
	table.SetCell(3, 1, tableCellContent("<under development!>"))

	table.SetCell(4, 0, tableCellTitle("Next Header"))
	table.SetCell(4, 1, tableCellContent("%x", i.NextHeader))

	table.SetCell(5, 0, tableCellTitle("Hop Limit"))
	table.SetCell(5, 1, tableCellContent("%d", i.HopLimit))

	table.SetCell(6, 0, tableCellTitle("Source Address"))
	table.SetCell(6, 1, tableCellContent("%s", i.StrSrcIPAddr()))

	table.SetCell(7, 0, tableCellTitle("Destination Address"))
	table.SetCell(7, 1, tableCellContent("%s", i.StrDstIPAddr()))

	return table
}
