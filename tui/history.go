package tui

import (
	"fmt"
	"strconv"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func NewPacketsHistoryTable() *tview.Table {
	h := tview.NewTable()
	h.SetTitle("History")
	h.SetTitleAlign(tview.AlignLeft)
	h.SetBorder(true)
	h.ScrollToBeginning()
	h.SetSelectionChangedFunc(func(row, column int) {
		c := h.GetCell(row, column)
		id, err := strconv.ParseInt(c.Text, 10, 64)
		if err == nil {
			// _ = v.renderSnapshot(id)
			_ = id
		}
	})
	h.SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorGray))

	return h
}

type HistoryRow struct {
	id *tview.TableCell

	addition *tview.TableCell
	deletion *tview.TableCell
	exitCode *tview.TableCell
}

func (t *tui) addSnapshotToView(id int64, r *HistoryRow) {
	t.table.InsertRow(0)
	t.table.SetCell(0, 0, r.id)
	t.table.SetCell(0, 1, r.addition)
	t.table.SetCell(0, 2, r.deletion)
	t.table.SetCell(0, 3, r.exitCode)

	// v.historyRowCount[id] = t.table.GetRowCount()

	// v.updateSelection()
}

func (t *tui) updateTable(passiveCh <-chan packemon.Passive) {
	id := int64(0)
	for passive := range passiveCh {
		viewers := []Viewer{}
		if passive.EthernetFrame != nil {
			viewers = append(viewers, &EthernetFrame{passive.EthernetFrame})
		}
		if passive.ARP != nil {
			viewers = append(viewers, &ARP{passive.ARP})
		}
		if passive.IPv4 != nil {
			viewers = append(viewers, &IPv4{passive.IPv4})
		}

		// s := v.getSnapShot(id)
		// idCell := tview.NewTableCell(strconv.FormatInt(s.id, 10)).SetTextColor(tview.Styles.SecondaryTextColor)
		idCell := tview.NewTableCell(strconv.FormatInt(id, 10)).SetTextColor(tview.Styles.SecondaryTextColor)
		additionCell := tview.NewTableCell(fmt.Sprintf("Dst: %x", passive.EthernetFrame.Header.Dst)).SetTextColor(tcell.ColorGreen)
		deletionCell := tview.NewTableCell(fmt.Sprintf("Src: %x", passive.EthernetFrame.Header.Src)).SetTextColor(tcell.ColorRed)
		exitCodeCell := tview.NewTableCell(fmt.Sprintf("Typ: %x", passive.EthernetFrame.Header.Typ)).SetTextColor(tcell.ColorYellow)

		r := &HistoryRow{
			id:       idCell,
			addition: additionCell,
			deletion: deletionCell,
			exitCode: exitCodeCell,
		}
		// v.historyRows[s.id] = r

		t.addSnapshotToView(id, r)
		id++
		t.app.Draw()
	}
}

// func (t *tui) updateView(passiveCh <-chan packemon.Passive) {
// 	for passive := range passiveCh {
// 		viewers := []Viewer{}
// 		if passive.EthernetFrame != nil {
// 			viewers = append(viewers, &EthernetFrame{passive.EthernetFrame})
// 		}
// 		if passive.ARP != nil {
// 			viewers = append(viewers, &ARP{passive.ARP})
// 		}
// 		if passive.IPv4 != nil {
// 			viewers = append(viewers, &IPv4{passive.IPv4})
// 		}

// 		go func() {
// 			t.app.QueueUpdate(func() {
// 				t.grid.Clear()
// 			})

// 			rows := make([]int, len(viewers))
// 			columns := make([]int, len(viewers))
// 			for i := range viewers {
// 				rows[i] = viewers[i].rows()
// 				columns[i] = viewers[i].columns()
// 			}
// 			t.grid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
// 			for i := range viewers {
// 				t.grid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false)
// 			}
// 			t.app.Draw()
// 		}()
// 	}
// }
