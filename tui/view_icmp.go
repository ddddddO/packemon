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
	return 20
}

func (i *ICMP) viewTable() *tview.Table {
	icmpTable := tview.NewTable().SetBorders(false)
	icmpTable.Box = tview.NewBox().SetBorder(true).SetTitle(" ICMP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	icmpTable.SetCell(0, 0, tview.NewTableCell(padding("Type")))
	icmpTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Typ))))

	icmpTable.SetCell(1, 0, tview.NewTableCell(padding("Code")))
	icmpTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Code))))

	icmpTable.SetCell(2, 0, tview.NewTableCell(padding("Checksum")))
	icmpTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Checksum))))

	icmpTable.SetCell(3, 0, tview.NewTableCell(padding("Identifier")))
	icmpTable.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.Identifier))))

	icmpTable.SetCell(4, 0, tview.NewTableCell(padding("Sequence")))
	icmpTable.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Sequence))))

	// icmpTable.SetCell(5, 0, tview.NewTableCell(padding("Data")))
	// icmpTable.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Data))))

	return icmpTable
}
