package tui

import (
	"fmt"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type DNS struct {
	*packemon.DNS
}

func (*DNS) rows() int {
	return 16
}

func (*DNS) columns() int {
	return 20
}

func (d *DNS) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" DNS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Transaction ID")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.TransactionID))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Flags")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Flags))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Questions")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Questions))))

	table.SetCell(3, 0, tview.NewTableCell(padding("AnswerRRs")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.AnswerRRs))))

	table.SetCell(4, 0, tview.NewTableCell(padding("AuthorityRRs")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.AuthorityRRs))))

	table.SetCell(5, 0, tview.NewTableCell(padding("AdditionalRRs")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.AdditionalRRs))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Queries: Domain")))
	table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Queries.Domain))))

	table.SetCell(7, 0, tview.NewTableCell(padding("Queries: Type")))
	table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Queries.Typ))))

	table.SetCell(8, 0, tview.NewTableCell(padding("Queries: Class")))
	table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Queries.Class))))

	return table
}
