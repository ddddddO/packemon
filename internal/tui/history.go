package tui

import (
	"fmt"
	"sync/atomic"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func NewPacketsHistoryTable() *tview.Table {
	h := tview.NewTable()
	h.SetTitle(" Packemon <Monitor> ")
	h.SetTitleAlign(tview.AlignLeft)
	h.SetBorder(true)
	h.ScrollToBeginning()
	h.SetSelectedStyle(tcell.StyleDefault.Background(tcell.ColorGray))

	return h
}

type HistoryRow struct {
	id *tview.TableCell

	// ethernet
	destinationMAC *tview.TableCell
	sourceMAC      *tview.TableCell
	typ            *tview.TableCell

	// arp

	// ipv4
	protocol          *tview.TableCell
	sourceIPAddr      *tview.TableCell
	destinationIPAddr *tview.TableCell
}

func (t *tui) insertToTable(r *HistoryRow) {
	t.table.InsertRow(0)
	t.table.SetCell(0, 0, r.id)

	// ethernet
	t.table.SetCell(0, 1, r.destinationMAC)
	t.table.SetCell(0, 2, r.sourceMAC)
	t.table.SetCell(0, 3, r.typ)

	// ipv4
	t.table.SetCell(0, 4, r.protocol)
	t.table.SetCell(0, 5, r.destinationIPAddr)
	t.table.SetCell(0, 6, r.sourceIPAddr)
}

func (t *tui) updateTable(passiveCh <-chan *packemon.Passive) {
	var id uint64 = 0
	for passive := range passiveCh {
		t.app.QueueUpdateDraw(func() {
			r := &HistoryRow{
				id:             tview.NewTableCell(fmt.Sprintf("%d", id)).SetTextColor(tcell.ColorWhite),
				destinationMAC: tview.NewTableCell(fmt.Sprintf("Dst:%x", passive.EthernetFrame.Header.Dst)).SetTextColor(tcell.Color38),
				sourceMAC:      tview.NewTableCell(fmt.Sprintf("Src:%x", passive.EthernetFrame.Header.Src)).SetTextColor(tcell.Color48),
				typ:            tview.NewTableCell(fmt.Sprintf("Type:%x", passive.EthernetFrame.Header.Typ)).SetTextColor(tcell.Color98),
			}

			r.protocol = tview.NewTableCell(fmt.Sprintf("Proto:%s", passive.HighLayerProto())).SetTextColor(tcell.Color50)

			if passive.IPv4 != nil {
				viewIPv4 := &IPv4{passive.IPv4}
				r.destinationIPAddr = tview.NewTableCell(fmt.Sprintf("DstIP:%s", viewIPv4.StrDstIPAddr())).SetTextColor(tcell.Color51)
				r.sourceIPAddr = tview.NewTableCell(fmt.Sprintf("SrcIP:%s", viewIPv4.StrSrcIPAddr())).SetTextColor(tcell.Color181)
			} else {
				r.destinationIPAddr = tview.NewTableCell(fmt.Sprintf("DstIP:%s", "-")).SetTextColor(tcell.Color51)
				r.sourceIPAddr = tview.NewTableCell(fmt.Sprintf("SrcIP:%s", "-")).SetTextColor(tcell.Color181)

			}

			t.storedPackets.Store(id, passive)
			t.insertToTable(r)
			atomic.AddUint64(&id, 1)
		})
	}
}
