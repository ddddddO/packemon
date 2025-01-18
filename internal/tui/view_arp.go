package tui

import (
	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type ARP struct {
	*packemon.ARP
}

func (*ARP) rows() int {
	return 13
}

func (*ARP) columns() int {
	return 30
}

func (a *ARP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tableCellTitle("Hardware Type"))
	table.SetCell(0, 1, tableCellContent("%x", a.HardwareType))

	table.SetCell(1, 0, tableCellTitle("Protocol Type"))
	table.SetCell(1, 1, tableCellContent("%x", a.ProtocolType))

	table.SetCell(2, 0, tableCellTitle("Hardware Addr Length"))
	table.SetCell(2, 1, tableCellContent("%x", a.HardwareAddrLength))

	table.SetCell(3, 0, tableCellTitle("Protocol Length"))
	table.SetCell(3, 1, tableCellContent("%x", a.ProtocolLength))

	table.SetCell(4, 0, tableCellTitle("Operation Code"))
	table.SetCell(4, 1, tableCellContent("%x", a.Operation))

	table.SetCell(5, 0, tableCellTitle("Sender Hardware Addr"))
	table.SetCell(5, 1, tableCellContent("%x", a.SenderHardwareAddr))

	table.SetCell(6, 0, tableCellTitle("Sender IP Addr"))
	table.SetCell(6, 1, tableCellContent("%x", a.SenderIPAddr))

	table.SetCell(7, 0, tableCellTitle("Target Hardware Addr"))
	table.SetCell(7, 1, tableCellContent("%x", a.TargetHardwareAddr))

	table.SetCell(8, 0, tableCellTitle("Target Hardware Addr"))
	table.SetCell(8, 1, tableCellContent("%x", a.TargetIPAddr))

	return table
}
