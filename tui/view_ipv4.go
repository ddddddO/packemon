package tui

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type IPv4 struct {
	*packemon.IPv4
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
