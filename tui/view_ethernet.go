package tui

import (
	"fmt"

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
	return 20
}

func (ef *EthernetFrame) viewTable() *tview.Table {
	ethTable := tview.NewTable().SetBorders(false)
	ethTable.Box = tview.NewBox().SetBorder(true).SetTitle(" Ethernet Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	ethTable.SetCell(0, 0, tview.NewTableCell(padding("Destination MAC Addr")))
	ethTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Dst))))

	ethTable.SetCell(1, 0, tview.NewTableCell(padding("Source MAC Addr")))
	ethTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Src))))

	ethTable.SetCell(2, 0, tview.NewTableCell(padding("Type")))
	ethTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Typ))))

	return ethTable
}
