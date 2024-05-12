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
	return 16
}

func (*IPv4) columns() int {
	return 30
}

func (i *IPv4) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" IPv4 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Version")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Version))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Hearder Length")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Ihl))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Type of Service")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Tos))))

	table.SetCell(3, 0, tview.NewTableCell(padding("Total Length")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.TotalLength))))

	table.SetCell(4, 0, tview.NewTableCell(padding("Identification")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Identification))))

	table.SetCell(5, 0, tview.NewTableCell(padding("Flags")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Flags))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Fragment Offset")))
	table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.FragmentOffset))))

	table.SetCell(7, 0, tview.NewTableCell(padding("TTL")))
	table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.Ttl))))

	table.SetCell(8, 0, tview.NewTableCell(padding("Protocol")))
	table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", i.Protocol, packemon.IPv4Protocols[i.Protocol]))))

	table.SetCell(9, 0, tview.NewTableCell(padding("Header Checksum")))
	table.SetCell(9, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.HeaderChecksum))))

	table.SetCell(10, 0, tview.NewTableCell(padding("Source Address")))
	table.SetCell(10, 1, tview.NewTableCell(padding(i.StrSrcIPAddr())))

	table.SetCell(11, 0, tview.NewTableCell(padding("Destination Address")))
	table.SetCell(11, 1, tview.NewTableCell(padding(i.StrDstIPAddr())))

	return table
}

func (i *IPv4) StrSrcIPAddr() string {
	return uint32ToStrIPv4Addr(i.SrcAddr)
}

func (i *IPv4) StrDstIPAddr() string {
	return uint32ToStrIPv4Addr(i.DstAddr)
}

func uint32ToStrIPv4Addr(byteAddr uint32) string {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, byteAddr)
	return net.IPv4(b[0], b[1], b[2], b[3]).String()
}
