package tui

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func NewPacketsHistoryTable() *tview.Table {
	h := tview.NewTable()
	h.SetTitle(TITLE_MONITOR)
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

	protocol          *tview.TableCell
	sourceIPAddr      *tview.TableCell
	destinationIPAddr *tview.TableCell
}

func (m *monitor) insertToTable(r *HistoryRow, columns string) {
	m.table.InsertRow(0)
	m.table.SetCell(0, 0, r.id)

	x := 1
	for i := range columns {
		switch columns[i] {
		case 'd':
			m.table.SetCell(0, x, r.destinationMAC)
		case 's':
			m.table.SetCell(0, x, r.sourceMAC)
		case 't':
			m.table.SetCell(0, x, r.typ)
		case 'p':
			m.table.SetCell(0, x, r.protocol)
		case 'D':
			m.table.SetCell(0, x, r.destinationIPAddr)
		case 'S':
			m.table.SetCell(0, x, r.sourceIPAddr)
		}
		x++
	}

	m.table.ScrollToBeginning()
}

func (m *monitor) updateTable(passiveCh <-chan *packemon.Passive, columns string) {
	var id uint64 = 0
	for passive := range passiveCh {
		time.Sleep(10 * time.Millisecond)

		m.app.QueueUpdateDraw(func() {
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
			} else if passive.IPv6 != nil {
				viewIPv6 := &IPv6{passive.IPv6}
				r.destinationIPAddr = tview.NewTableCell(fmt.Sprintf("DstIP:%s", viewIPv6.StrDstIPAddr())).SetTextColor(tcell.Color51)
				r.sourceIPAddr = tview.NewTableCell(fmt.Sprintf("SrcIP:%s", viewIPv6.StrSrcIPAddr())).SetTextColor(tcell.Color181)
			} else {
				r.destinationIPAddr = tview.NewTableCell(fmt.Sprintf("DstIP:%s", "-")).SetTextColor(tcell.Color51)
				r.sourceIPAddr = tview.NewTableCell(fmt.Sprintf("SrcIP:%s", "-")).SetTextColor(tcell.Color181)

			}

			m.storedPackets.Store(id, passive)
			m.insertToTable(r, columns)
			atomic.AddUint64(&id, 1)
		})
	}
}
