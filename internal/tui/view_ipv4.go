package tui

import (
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

	table.SetCell(0, 0, tableCellTitle("Version"))
	table.SetCell(0, 1, tableCellContent("%x", i.Version))

	table.SetCell(1, 0, tableCellTitle("Hearder Length"))
	table.SetCell(1, 1, tableCellContent("%x", i.Ihl))

	table.SetCell(2, 0, tableCellTitle("Type of Service"))
	table.SetCell(2, 1, tableCellContent("%x", i.Tos))

	table.SetCell(3, 0, tableCellTitle("Total Length"))
	table.SetCell(3, 1, tableCellContent("%d", i.TotalLength))

	table.SetCell(4, 0, tableCellTitle("Identification"))
	table.SetCell(4, 1, tableCellContent("%x", i.Identification))

	table.SetCell(5, 0, tableCellTitle("Flags"))
	table.SetCell(5, 1, tableCellContent("%x", i.Flags))

	table.SetCell(6, 0, tableCellTitle("Fragment Offset"))
	table.SetCell(6, 1, tableCellContent("%d", i.FragmentOffset))

	table.SetCell(7, 0, tableCellTitle("TTL"))
	table.SetCell(7, 1, tableCellContent("%d", i.Ttl))

	table.SetCell(8, 0, tableCellTitle("Protocol"))
	table.SetCell(8, 1, tableCellContent("%x (%s)", i.Protocol, packemon.IPv4Protocols[i.Protocol]))

	table.SetCell(9, 0, tableCellTitle("Header Checksum"))
	table.SetCell(9, 1, tableCellContent("%x", i.HeaderChecksum))

	table.SetCell(10, 0, tableCellTitle("Source Address"))
	table.SetCell(10, 1, tableCellContent("%s", i.StrSrcIPAddr()))

	table.SetCell(11, 0, tableCellTitle("Destination Address"))
	table.SetCell(11, 1, tableCellContent("%s", i.StrDstIPAddr()))

	return table
}
