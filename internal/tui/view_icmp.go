package tui

import (
	"fmt"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type ICMP struct {
	*packemon.ICMP
}

func (*ICMP) rows() int {
	return 8
}

func (*ICMP) columns() int {
	return 30
}

func (i *ICMP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" ICMP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Type")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Typ))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Code")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Code))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Checksum")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Checksum))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Identifier")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.Identifier))))

	table.SetCell(4, 0, tview.NewTableCell(padding("Sequence")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Sequence))))

	// table.SetCell(5, 0, tview.NewTableCell(padding("Data")))
	// table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Data))))

	return table
}
