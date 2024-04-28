package main

import (
	"fmt"
	"strings"

	"github.com/rivo/tview"
)

type viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

// TODO: refactor
// func view(ethernetFrame *ethernetFrame, arp *arp) error {
func view(viewers ...viewer) error {
	rows := make([]int, len(viewers))
	columns := make([]int, len(viewers))
	for i := range viewers {
		rows[i] = viewers[i].rows()
		columns[i] = viewers[i].columns()
	}
	grid := tview.NewGrid().SetRows(rows...).SetColumns(columns...).SetBorders(false)
	for i := range viewers {
		grid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false)
	}
	grid.Box = tview.NewBox().SetBorder(true).SetTitle(" Packemon ")

	if err := tview.NewApplication().SetRoot(grid, true).Run(); err != nil {
		return err
	}
	return nil
}

func (ef *ethernetFrame) rows() int {
	return 10
}

func (ef *ethernetFrame) columns() int {
	return 20
}

func (ef *ethernetFrame) viewTable() *tview.Table {
	ethTable := tview.NewTable().SetBorders(true)
	ethTable.Box = tview.NewBox().SetBorder(true).SetTitle(" Ethernet Header ")

	ethTable.SetCell(0, 0, tview.NewTableCell(padding("Destination MAC Addr")))
	ethTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.header.dst))))

	ethTable.SetCell(1, 0, tview.NewTableCell(padding("Source MAC Addr")))
	ethTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.header.src))))

	ethTable.SetCell(2, 0, tview.NewTableCell(padding("Type")))
	ethTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.header.typ))))

	return ethTable
}

func (a *arp) rows() int {
	return 22
}

func (a *arp) columns() int {
	return 20
}

func (a *arp) viewTable() *tview.Table {
	arpTable := tview.NewTable().SetBorders(true)
	arpTable.Box = tview.NewBox().SetBorder(true).SetTitle(" ARP ")

	arpTable.SetCell(0, 0, tview.NewTableCell(padding("Hardware Type")))
	arpTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.hardwareType))))

	arpTable.SetCell(1, 0, tview.NewTableCell(padding("Protocol Type")))
	arpTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.protocolType))))

	arpTable.SetCell(2, 0, tview.NewTableCell(padding("Hardware Addr Length")))
	arpTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.hardwareAddrLength))))

	arpTable.SetCell(3, 0, tview.NewTableCell(padding("Protocol Length")))
	arpTable.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.protocolLength))))

	arpTable.SetCell(4, 0, tview.NewTableCell(padding("Operation Code")))
	arpTable.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.operation))))

	arpTable.SetCell(5, 0, tview.NewTableCell(padding("Sender Hardware Addr")))
	arpTable.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.senderHardwareAddr))))

	arpTable.SetCell(6, 0, tview.NewTableCell(padding("Sender IP Addr")))
	arpTable.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.senderIPAddr))))

	arpTable.SetCell(7, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	arpTable.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.targetHardwareAddr))))

	arpTable.SetCell(8, 0, tview.NewTableCell(padding("Target Hardware Addr")))
	arpTable.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", a.targetIPAddr))))

	return arpTable
}

func padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}
