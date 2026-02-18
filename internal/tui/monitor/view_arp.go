package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type ARP struct {
	*packemon.ARP
}

func (*ARP) rows() int {
	return 13
}

func (*ARP) columns() int {
	return 30
}

func (a *ARP) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" ARP ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Hardware Type"))
	table.SetCell(0, 1, tui.TableCellContent("%#x", a.HardwareType))

	table.SetCell(1, 0, tui.TableCellTitle("Protocol Type"))
	table.SetCell(1, 1, tui.TableCellContent("%#x", a.ProtocolType))

	table.SetCell(2, 0, tui.TableCellTitle("Hardware Addr Length"))
	table.SetCell(2, 1, tui.TableCellContent("%#x", a.HardwareAddrLength))

	table.SetCell(3, 0, tui.TableCellTitle("Protocol Length"))
	table.SetCell(3, 1, tui.TableCellContent("%#x", a.ProtocolLength))

	table.SetCell(4, 0, tui.TableCellTitle("Operation Code"))
	table.SetCell(4, 1, tui.TableCellContent("%#x", a.Operation))

	table.SetCell(5, 0, tui.TableCellTitle("Sender Hardware Addr"))
	table.SetCell(5, 1, tui.TableCellContent("%#x", a.SenderHardwareAddr))

	table.SetCell(6, 0, tui.TableCellTitle("Sender IP Addr"))
	table.SetCell(6, 1, tui.TableCellContent("%#x", a.SenderIPAddr))

	table.SetCell(7, 0, tui.TableCellTitle("Target Hardware Addr"))
	table.SetCell(7, 1, tui.TableCellContent("%#x", a.TargetHardwareAddr))

	table.SetCell(8, 0, tui.TableCellTitle("Target Hardware Addr"))
	table.SetCell(8, 1, tui.TableCellContent("%#x", a.TargetIPAddr))

	return table
}
