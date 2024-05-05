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
	return 22
}

func (*ARP) columns() int {
	return 20
}

func (a *ARP) viewTable() *tview.Table {
	arpTable := tview.NewTable().SetBorders(true)
	arpTable.Box = tview.NewBox().SetBorder(true).SetTitle(" ARP ")

	arpTable.SetCell(0, 0, tview.NewTableCell(padding("Hardware Type")))
	arpTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.HardwareType))))

	arpTable.SetCell(1, 0, tview.NewTableCell(padding("Protocol Type")))
	arpTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.ProtocolType))))

	arpTable.SetCell(2, 0, tview.NewTableCell(padding("Hardware Addr Length")))
	arpTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.HardwareAddrLength))))

	arpTable.SetCell(3, 0, tview.NewTableCell(padding("Protocol Length")))
	arpTable.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.ProtocolLength))))

	arpTable.SetCell(4, 0, tview.NewTableCell(padding("Operation Code")))
	arpTable.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.Operation))))

	arpTable.SetCell(5, 0, tview.NewTableCell(padding("Sender Hardware Addr")))
	arpTable.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.SenderHardwareAddr))))

	arpTable.SetCell(6, 0, tview.NewTableCell(padding("Sender IP Addr")))
	arpTable.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.SenderIPAddr))))

	arpTable.SetCell(7, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	arpTable.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.TargetHardwareAddr))))

	arpTable.SetCell(8, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	arpTable.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.TargetIPAddr))))

	return arpTable
}
