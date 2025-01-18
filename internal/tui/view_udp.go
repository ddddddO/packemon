package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type UDP struct {
	*packemon.UDP
}

func (*UDP) rows() int {
	return 8
}

func (*UDP) columns() int {
	return 30
}

func (u *UDP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" UDP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Src Port"))
	table.SetCell(0, 1, tableCellContent("%x (%d)", u.SrcPort, u.SrcPort))

	table.SetCell(1, 0, tableCellTitle("Dst Port"))
	table.SetCell(1, 1, tableCellContent("%x (%d)", u.DstPort, u.DstPort))

	table.SetCell(2, 0, tableCellTitle("Length"))
	table.SetCell(2, 1, tableCellContent("%x", u.Length))

	table.SetCell(3, 0, tableCellTitle("Checksum"))
	table.SetCell(3, 1, tableCellContent("%x", u.Checksum))

	return table
}
