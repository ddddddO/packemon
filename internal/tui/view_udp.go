package tui

import (
	"fmt"

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

	table.SetCell(0, 0, tview.NewTableCell(padding("Src Port")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", u.SrcPort, u.SrcPort))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Dst Port")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", u.DstPort, u.DstPort))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Length")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", u.Length))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Checksum")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", u.Checksum))))

	return table
}
