package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type TCP struct {
	*packemon.TCP
}

func (*TCP) rows() int {
	return 16
}

func (*TCP) columns() int {
	return 30
}

func (t *TCP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" TCP Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Src Port"))
	table.SetCell(0, 1, tui.TableCellContent("%x (%d)", t.SrcPort, t.SrcPort))

	table.SetCell(1, 0, tui.TableCellTitle("Dst Port"))
	table.SetCell(1, 1, tui.TableCellContent("%x (%d)", t.DstPort, t.DstPort))

	table.SetCell(2, 0, tui.TableCellTitle("Sequence"))
	table.SetCell(2, 1, tui.TableCellContent("%x", t.Sequence))

	table.SetCell(3, 0, tui.TableCellTitle("Acknowledgment"))
	table.SetCell(3, 1, tui.TableCellContent("%x", t.Acknowledgment))

	table.SetCell(4, 0, tui.TableCellTitle("HeaderLength"))
	table.SetCell(4, 1, tui.TableCellContent("%x", t.HeaderLength>>4))

	table.SetCell(5, 0, tui.TableCellTitle("Flags"))
	table.SetCell(5, 1, tui.TableCellContent("%x", t.Flags))

	table.SetCell(6, 0, tui.TableCellTitle("Window"))
	table.SetCell(6, 1, tui.TableCellContent("%x", t.Window))

	table.SetCell(7, 0, tui.TableCellTitle("Checksum"))
	table.SetCell(7, 1, tui.TableCellContent("%x", t.Checksum))

	table.SetCell(8, 0, tui.TableCellTitle("UrgentPointer"))
	table.SetCell(8, 1, tui.TableCellContent("%x", t.UrgentPointer))

	table.SetCell(9, 0, tui.TableCellTitle("Options"))
	table.SetCell(9, 1, tui.TableCellContent("%x", t.Options))

	return table
}
