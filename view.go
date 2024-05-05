package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/rivo/tview"
)

type viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

func updateView(viewersCh <-chan []viewer) {
	for viewers := range viewersCh {
		globalTviewApp.QueueUpdateDraw(func() {
			rows := make([]int, len(viewers))
			columns := make([]int, len(viewers))
			for i := range viewers {
				rows[i] = viewers[i].rows()
				columns[i] = viewers[i].columns()
			}
			globalTviewGrid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
			for i := range viewers {
				globalTviewGrid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false)
			}
		})
	}
}

func (*EthernetFrame) rows() int {
	return 10
}

func (*EthernetFrame) columns() int {
	return 20
}

func (ef *EthernetFrame) viewTable() *tview.Table {
	ethTable := tview.NewTable().SetBorders(true)
	ethTable.Box = tview.NewBox().SetBorder(true).SetTitle(" Ethernet Header ")

	ethTable.SetCell(0, 0, tview.NewTableCell(padding("Destination MAC Addr")))
	ethTable.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Dst))))

	ethTable.SetCell(1, 0, tview.NewTableCell(padding("Source MAC Addr")))
	ethTable.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Src))))

	ethTable.SetCell(2, 0, tview.NewTableCell(padding("Type")))
	ethTable.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", ef.Header.Typ))))

	return ethTable
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

func (*IPv4) rows() int {
	return 28
}

func (*IPv4) columns() int {
	return 20
}

func (i *IPv4) viewTable() *tview.Table {
	ipv4Table := tview.NewTable().SetBorders(true)
	ipv4Table.Box = tview.NewBox().SetBorder(true).SetTitle(" IPv4 Header ")

	ipv4Table.SetCell(0, 0, tview.NewTableCell(padding("Version")))
	ipv4Table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Version))))

	ipv4Table.SetCell(1, 0, tview.NewTableCell(padding("Hearder Length")))
	ipv4Table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Ihl))))

	ipv4Table.SetCell(2, 0, tview.NewTableCell(padding("Type of Service")))
	ipv4Table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Tos))))

	ipv4Table.SetCell(3, 0, tview.NewTableCell(padding("Total Length")))
	ipv4Table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.TotalLength))))

	ipv4Table.SetCell(4, 0, tview.NewTableCell(padding("Identification")))
	ipv4Table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Identification))))

	ipv4Table.SetCell(5, 0, tview.NewTableCell(padding("Flags")))
	ipv4Table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Flags))))

	ipv4Table.SetCell(6, 0, tview.NewTableCell(padding("Fragment Offset")))
	ipv4Table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.FragmentOffset))))

	ipv4Table.SetCell(7, 0, tview.NewTableCell(padding("TTL")))
	ipv4Table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.Ttl))))

	ipv4Table.SetCell(8, 0, tview.NewTableCell(padding("Protocol")))
	ipv4Table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.Protocol))))

	ipv4Table.SetCell(9, 0, tview.NewTableCell(padding("Header Checksum")))
	ipv4Table.SetCell(9, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.HeaderChecksum))))

	ipv4Table.SetCell(10, 0, tview.NewTableCell(padding("Source Address")))
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.SrcAddr)
	ipv4Table.SetCell(10, 1, tview.NewTableCell(padding(net.IPv4(b[0], b[1], b[2], b[3]).String())))

	ipv4Table.SetCell(11, 0, tview.NewTableCell(padding("Destination Address")))
	b = make([]byte, 4)
	binary.BigEndian.PutUint32(b, i.DstAddr)
	ipv4Table.SetCell(11, 1, tview.NewTableCell(padding(net.IPv4(b[0], b[1], b[2], b[3]).String())))

	return ipv4Table
}

func padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}
