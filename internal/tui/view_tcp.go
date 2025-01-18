package tui

import (
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

	table.SetCell(0, 0, tableCellTitle("Src Port"))
	table.SetCell(0, 1, tableCellContent("%x (%d)", t.SrcPort, t.SrcPort))

	table.SetCell(1, 0, tableCellTitle("Dst Port"))
	table.SetCell(1, 1, tableCellContent("%x (%d)", t.DstPort, t.DstPort))

	table.SetCell(2, 0, tableCellTitle("Sequence"))
	table.SetCell(2, 1, tableCellContent("%x", t.Sequence))

	table.SetCell(3, 0, tableCellTitle("Acknowledgment"))
	table.SetCell(3, 1, tableCellContent("%x", t.Acknowledgment))

	table.SetCell(4, 0, tableCellTitle("HeaderLength"))
	table.SetCell(4, 1, tableCellContent("%x", t.HeaderLength>>4))

	table.SetCell(5, 0, tableCellTitle("Flags"))
	table.SetCell(5, 1, tableCellContent("%x", t.Flags))

	table.SetCell(6, 0, tableCellTitle("Window"))
	table.SetCell(6, 1, tableCellContent("%x", t.Window))

	table.SetCell(7, 0, tableCellTitle("Checksum"))
	table.SetCell(7, 1, tableCellContent("%x", t.Checksum))

	table.SetCell(8, 0, tableCellTitle("UrgentPointer"))
	table.SetCell(8, 1, tableCellContent("%x", t.UrgentPointer))

	table.SetCell(9, 0, tableCellTitle("Options"))
	table.SetCell(9, 1, tableCellContent("%x", t.Options))

	return table
}
