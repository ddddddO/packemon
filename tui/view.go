package tui

import (
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type Viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

func (t *tui) updateView(passiveCh <-chan packemon.Passive) {
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

		go func() {
			t.app.QueueUpdate(func() {
				t.grid.Clear()
			})

			rows := make([]int, len(viewers))
			columns := make([]int, len(viewers))
			for i := range viewers {
				rows[i] = viewers[i].rows()
				columns[i] = viewers[i].columns()
			}
			t.grid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
			for i := range viewers {
				t.grid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false)
			}
			t.app.Draw()
		}()
	}
}

func padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}
