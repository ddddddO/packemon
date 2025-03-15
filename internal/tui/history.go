package tui

import (
	"fmt"
	"strings"
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

func (m *monitor) newHistoryRow(passive *packemon.Passive, id uint64) *HistoryRow {
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
	return r
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

// パケット一覧の各値にfilter文字列が含まれていればそれを表示、一旦
// TODO: ゆくゆくはportだけで絞りたいとか細かく制御したいかも
func (m *monitor) doFilter(passive *packemon.Passive, id uint64) {
	if passive == nil {
		return
	}
	// filter 文字列が空ならすべて表示
	if len(strings.TrimSpace(m.filterValue)) == 0 {
		m.insertToTable(m.newHistoryRow(passive, id), m.columns)
		return
	}

	if passive.EthernetFrame != nil {
		if strings.Contains(passive.EthernetFrame.Header.Dst.String(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
		if strings.Contains(passive.EthernetFrame.Header.Src.String(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
		if strings.Contains(string(passive.EthernetFrame.Header.Typ), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
	}

	if passive.IPv4 != nil {
		if strings.Contains(passive.IPv4.StrSrcIPAddr(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}

		if strings.Contains(passive.IPv4.StrDstIPAddr(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
	}

	if passive.IPv6 != nil {
		if strings.Contains(passive.IPv6.StrSrcIPAddr(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
		if strings.Contains(passive.IPv6.StrDstIPAddr(), m.filterValue) {
			m.insertToTable(m.newHistoryRow(passive, id), m.columns)
			return
		}
	}

	if strings.Contains(passive.HighLayerProto(), m.filterValue) {
		m.insertToTable(m.newHistoryRow(passive, id), m.columns)
		return
	}
}

func (m *monitor) updateTable(passiveCh <-chan *packemon.Passive, columns string) {
	var id uint64 = 0
	for passive := range passiveCh {
		time.Sleep(10 * time.Millisecond)

		m.app.QueueUpdateDraw(func() {
			m.storedPackets.Store(id, passive)
			m.doFilter(passive, id)
			atomic.AddUint64(&id, 1)
		})
	}
}
