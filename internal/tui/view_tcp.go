package tui

import (
	"fmt"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type TCP struct {
	*packemon.TCP
}

func (*TCP) rows() int {
	return 16
}

func (*TCP) columns() int {
	return 30
}

func (t *TCP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TCP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Src Port")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", t.SrcPort, t.SrcPort))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Dst Port")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", t.DstPort, t.DstPort))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Sequence")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Sequence))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Acknowledgment")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Acknowledgment))))

	table.SetCell(4, 0, tview.NewTableCell(padding("HeaderLength")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.HeaderLength>>4))))

	table.SetCell(5, 0, tview.NewTableCell(padding("Flags")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Flags))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Window")))
	table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Window))))

	table.SetCell(7, 0, tview.NewTableCell(padding("Checksum")))
	table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Checksum))))

	table.SetCell(8, 0, tview.NewTableCell(padding("UrgentPointer")))
	table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.UrgentPointer))))

	table.SetCell(9, 0, tview.NewTableCell(padding("Options")))
	table.SetCell(9, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", t.Options))))

	return table
}
