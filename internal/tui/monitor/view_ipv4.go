package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
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

	table.SetCell(0, 0, tui.TableCellTitle("Version"))
	table.SetCell(0, 1, tui.TableCellContent("%#x", i.Version))

	table.SetCell(1, 0, tui.TableCellTitle("Hearder Length"))
	table.SetCell(1, 1, tui.TableCellContent("%#x", i.Ihl))

	table.SetCell(2, 0, tui.TableCellTitle("Type of Service"))
	table.SetCell(2, 1, tui.TableCellContent("%#x", i.Tos))

	table.SetCell(3, 0, tui.TableCellTitle("Total Length"))
	table.SetCell(3, 1, tui.TableCellContent("%d", i.TotalLength))

	table.SetCell(4, 0, tui.TableCellTitle("Identification"))
	table.SetCell(4, 1, tui.TableCellContent("%#x", i.Identification))

	table.SetCell(5, 0, tui.TableCellTitle("Flags"))
	table.SetCell(5, 1, tui.TableCellContent("%#x", i.Flags))

	table.SetCell(6, 0, tui.TableCellTitle("Fragment Offset"))
	table.SetCell(6, 1, tui.TableCellContent("%d", i.FragmentOffset))

	table.SetCell(7, 0, tui.TableCellTitle("TTL"))
	table.SetCell(7, 1, tui.TableCellContent("%d", i.Ttl))

	table.SetCell(8, 0, tui.TableCellTitle("Protocol"))
	table.SetCell(8, 1, tui.TableCellContent("%#x (%s)", i.Protocol, packemon.IPv4Protocols[i.Protocol]))

	table.SetCell(9, 0, tui.TableCellTitle("Header Checksum"))
	table.SetCell(9, 1, tui.TableCellContent("%#x", i.HeaderChecksum))

	table.SetCell(10, 0, tui.TableCellTitle("Source Address"))
	table.SetCell(10, 1, tui.TableCellContent("%s", i.StrSrcIPAddr()))

	table.SetCell(11, 0, tui.TableCellTitle("Destination Address"))
	table.SetCell(11, 1, tui.TableCellContent("%s", i.StrDstIPAddr()))

	return table
}
