package tui

import (
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

func (t *tui) updateView(passive *packemon.Passive) {
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
	if passive.ICMP != nil {
		viewers = append(viewers, &ICMP{passive.ICMP})
	}
	if passive.TCP != nil {
		viewers = append(viewers, &TCP{passive.TCP})
	}
	if passive.UDP != nil {
		viewers = append(viewers, &UDP{passive.UDP})
	}
	if passive.DNS != nil {
		viewers = append(viewers, &DNS{passive.DNS})
	}
	if passive.HTTP != nil {
		viewers = append(viewers, &HTTP{passive.HTTP})
	}

	go func(viewers []Viewer) {
		t.app.QueueUpdate(func() {
			t.grid.Clear()
		})

		rows := make([]int, len(viewers))
		columns := make([]int, len(viewers))
		for i := range viewers {
			rows[i] = viewers[i].rows()
			columns[i] = viewers[i].columns()
		}
		t.grid.RemoveItem(t.grid) // ほんと？
		t.grid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
		for i := range viewers {
			t.grid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false) // focus=true にするとスクロールしない
		}
		t.grid.SetInputCapture(
			func(event *tcell.EventKey) *tcell.EventKey {
				if event.Key() == tcell.KeyEscape {
					t.grid.Clear()
					t.pages.SwitchToPage("history")
				}
				return event
			})
		t.pages.AddAndSwitchToPage("packetDetail", t.grid, true)
		t.app.Draw()
	}(viewers)
}

func padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}
