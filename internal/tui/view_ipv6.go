package tui

import (
	"fmt"
	"net"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type IPv6 struct {
	*packemon.IPv6
}

func (*IPv6) rows() int {
	return 16
}

func (*IPv6) columns() int {
	return 30
}

func (i *IPv6) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" IPv6 Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Version")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.Version))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Traffic Class")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.TrafficClass))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Flow Label")))
	table.SetCell(2, 1, tview.NewTableCell(padding("<under development!>")))

	table.SetCell(3, 0, tview.NewTableCell(padding("Payload Length")))
	table.SetCell(3, 1, tview.NewTableCell(padding("<under development!>")))

	table.SetCell(4, 0, tview.NewTableCell(padding("Next Header")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", i.NextHeader))))

	table.SetCell(5, 0, tview.NewTableCell(padding("Hop Limit")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%d", i.HopLimit))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Source Address")))
	table.SetCell(6, 1, tview.NewTableCell(padding(i.StrSrcIPAddr())))

	table.SetCell(7, 0, tview.NewTableCell(padding("Destination Address")))
	table.SetCell(7, 1, tview.NewTableCell(padding(i.StrDstIPAddr())))

	return table
}

func (i *IPv6) StrSrcIPAddr() string {
	return uintsToStrIPv6Addr(i.SrcAddr)
}

func (i *IPv6) StrDstIPAddr() string {
	return uintsToStrIPv6Addr(i.DstAddr)
}

func uintsToStrIPv6Addr(byteAddr []uint8) string {
	ipv6Addr := net.IP(byteAddr)
	return ipv6Addr.To16().String()
}
