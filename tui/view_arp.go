package tui

import (
	"fmt"

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

	table.SetCell(0, 0, tview.NewTableCell(padding("Hardware Type")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.HardwareType))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Protocol Type")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.ProtocolType))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Hardware Addr Length")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.HardwareAddrLength))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Protocol Length")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.ProtocolLength))))

	table.SetCell(4, 0, tview.NewTableCell(padding("Operation Code")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.Operation))))

	table.SetCell(5, 0, tview.NewTableCell(padding("Sender Hardware Addr")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.SenderHardwareAddr))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Sender IP Addr")))
	table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.SenderIPAddr))))

	table.SetCell(7, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.TargetHardwareAddr))))

	table.SetCell(8, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.TargetIPAddr))))

	return table
}
