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
			m.storedMaxID.set(id)
			m.filterAndInsertToTable(passive, id)
			defer func() {
				atomic.AddUint64(&id, 1)
			}()

			if m.limit <= 0 {
				return
			}

			// TODO: 若干ちぐはぐなことになってる
			// 制限超えた都度キャッシュから削除するものの、レコード数が制限数の倍数に到達しないとテーブルを更新(サイズ削減)しないから、テーブル上見えてるけどキャッシュから消えてるから選択しても表示されない、みたいなことが起きる
			removingID := id - uint64(m.limit)
			if removingID >= 0 {
				m.storedPackets.Delete(removingID)

				if id != 0 && id%uint64(m.limit) == 0 {
					m.reCreateTable()
					return
				}
			}
		})
	}
}

func (m *monitor) reCreateTable() {
	// 一回クリア
	m.table.Clear()
	m.setHeader()

	// filter 処理(なお、filter文字列が空なら全部表示)
	storedMaxID := int(m.storedMaxID.get())
	begin := 0
	if m.limit > 0 && storedMaxID-m.limit > 0 {
		begin = storedMaxID - m.limit
	}
	for id := begin; id <= storedMaxID; id++ {
		value, ok := m.storedPackets.Load(uint64(id))
		if !ok {
			continue
		}
		passive, ok := value.(*packemon.Passive)
		if !ok {
			continue
		}
		m.filterAndInsertToTable(passive, uint64(id))
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
	currentRow, currentColumn := m.table.GetSelection()

	if m.prepend {
		m.table.InsertRow(1)
		m.table.SetCell(1, 0, r.id)
		m.insertRow(1, r)

		// パケットが届き、行が追加されてもカーソルをあてていた行をずらさずに固定するため
		m.table = m.table.Select(currentRow+1, currentColumn)
	} else {
		next := m.table.GetRowCount()
		m.table.InsertRow(next)
		m.table.SetCell(next, 0, r.id)
		m.insertRow(next, r)

		m.table = m.table.Select(currentRow, currentColumn)
	}
}

func (m *monitor) insertRow(y int, r *HistoryRow) {
	x := 1
	for i := range m.columns {
		switch m.columns[i] {
		case 'd':
			m.table.SetCell(y, x, r.destinationMAC)
		case 's':
			m.table.SetCell(y, x, r.sourceMAC)
		case 't':
			m.table.SetCell(y, x, r.typ)
		case 'p':
			m.table.SetCell(y, x, r.protocol)
		case 'D':
			m.table.SetCell(y, x, r.destinationIPAddr)
		case 'S':
			m.table.SetCell(y, x, r.sourceIPAddr)
		case 'i':
			m.table.SetCell(y, x, r.info)
		}
		x++
	}
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

	info *tview.TableCell
}

func (m *monitor) newHistoryRow(passive *packemon.Passive, id uint64) *HistoryRow {
	r := &HistoryRow{
		id:             tview.NewTableCell(fmt.Sprintf("%d", id)).SetTextColor(tcell.ColorWhite),
		destinationMAC: tview.NewTableCell(fmt.Sprintf("%x", passive.EthernetFrame.Header.Dst)).SetTextColor(headers['d'].Color),
		sourceMAC:      tview.NewTableCell(fmt.Sprintf("%x", passive.EthernetFrame.Header.Src)).SetTextColor(headers['s'].Color),
		typ:            tview.NewTableCell(fmt.Sprintf("%x", passive.EthernetFrame.Header.Typ)).SetTextColor(headers['t'].Color),
	}

	r.protocol = tview.NewTableCell(passive.HighLayerProto()).SetTextColor(headers['p'].Color)

	if passive.IPv4 != nil {
		r.destinationIPAddr = tview.NewTableCell(passive.IPv4.StrDstIPAddr()).SetTextColor(headers['D'].Color)
		r.sourceIPAddr = tview.NewTableCell(passive.IPv4.StrSrcIPAddr()).SetTextColor(headers['S'].Color)
	} else if passive.IPv6 != nil {
		r.destinationIPAddr = tview.NewTableCell(passive.IPv6.StrDstIPAddr()).SetTextColor(headers['D'].Color)
		r.sourceIPAddr = tview.NewTableCell(passive.IPv6.StrSrcIPAddr()).SetTextColor(headers['S'].Color)
	} else {
		r.destinationIPAddr = tview.NewTableCell("-").SetTextColor(headers['D'].Color)
		r.sourceIPAddr = tview.NewTableCell("-").SetTextColor(headers['S'].Color)
	}

	if passive.TCP != nil {
		r.info = tview.NewTableCell(fmt.Sprintf("%d <- %d |%s|", passive.TCP.DstPort, passive.TCP.SrcPort, passive.TCP.Flags)).SetTextColor(headers['i'].Color)
	} else if passive.UDP != nil {
		r.info = tview.NewTableCell(fmt.Sprintf("%d <- %d", passive.UDP.DstPort, passive.UDP.SrcPort)).SetTextColor(headers['i'].Color)
	}

	return r
}
