package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
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

	table.SetCell(0, 0, tui.TableCellTitle("Version"))
	table.SetCell(0, 1, tui.TableCellContent("%#x", i.Version))

	table.SetCell(1, 0, tui.TableCellTitle("Traffic Class"))
	table.SetCell(1, 1, tui.TableCellContent("%#x", i.TrafficClass))

	table.SetCell(2, 0, tui.TableCellTitle("Flow Label"))
	table.SetCell(2, 1, tui.TableCellContent("%#x", i.FlowLabel))

	table.SetCell(3, 0, tui.TableCellTitle("Payload Length"))
	table.SetCell(3, 1, tui.TableCellContent("%#x", i.PayloadLength))

	table.SetCell(4, 0, tui.TableCellTitle("Next Header"))
	table.SetCell(4, 1, tui.TableCellContent("%#x", i.NextHeader))

	table.SetCell(5, 0, tui.TableCellTitle("Hop Limit"))
	table.SetCell(5, 1, tui.TableCellContent("%d", i.HopLimit))

	table.SetCell(6, 0, tui.TableCellTitle("Source Address"))
	table.SetCell(6, 1, tui.TableCellContent("%s", i.StrSrcIPAddr()))

	table.SetCell(7, 0, tui.TableCellTitle("Destination Address"))
	table.SetCell(7, 1, tui.TableCellContent("%s", i.StrDstIPAddr()))

	// TODO: Option. 拡張ヘッダ

	return table
}
