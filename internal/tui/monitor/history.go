package monitor

import (
	"fmt"
	"sync/atomic"
	"time"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

func (m *monitor) updateTable() {
	var id uint64 = 0
	for passive := range m.passiveCh {
		time.Sleep(10 * time.Millisecond)

		m.app.QueueUpdateDraw(func() {
			m.storedPackets.Store(id, passive)
			m.filterAndInsertToTable(passive, id)
			m.storedMaxID.set(id)
			atomic.AddUint64(&id, 1)
		})
	}
}

func (m *monitor) reCreateTable() {
	// 一回クリア
	m.table.Clear()

	// filter 処理(なお、filter文字列が空なら全部表示)
	for id := range m.storedMaxID.get() {
		value, ok := m.storedPackets.Load(id)
		if !ok {
			continue
		}
		passive, ok := value.(*packemon.Passive)
		if !ok {
			continue
		}
		m.filterAndInsertToTable(passive, id)
	}
}

// パケット一覧の各値にfilter文字列が含まれていればそれを表示、一旦
// TODO: ゆくゆくはportだけで絞りたいとか細かく制御したいかも
func (m *monitor) filterAndInsertToTable(passive *packemon.Passive, id uint64) {
	if passive == nil {
		return
	}

	if m.filter.contains(passive) {
		m.insertToTable(m.newHistoryRow(passive, id))
	}
}

func (m *monitor) insertToTable(r *HistoryRow) {
	m.table.InsertRow(0)
	m.table.SetCell(0, 0, r.id)

	x := 1
	for i := range m.columns {
		switch m.columns[i] {
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

func NewPacketsHistoryTable() *tview.Table {
	h := tview.NewTable()
	h.SetTitleAlign(tview.AlignLeft)
	h.SetBorder(false)
	h.ScrollToBeginning()
	h.SetBorderPadding(1, 1, 1, 1)
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
