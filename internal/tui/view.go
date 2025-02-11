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
	}(passiveToViewers(passive))
}

func passiveToViewers(passive *packemon.Passive) []Viewer {
	viewers := []Viewer{}
	hexdump := &HexadecimalDump{}
	if passive.EthernetFrame != nil {
		viewers = append(viewers, &EthernetFrame{passive.EthernetFrame})
		hexdump.EthernetFrame = passive.EthernetFrame
	}
	if passive.ARP != nil {
		viewers = append(viewers, &ARP{passive.ARP})
		hexdump.ARP = passive.ARP
	}
	if passive.IPv4 != nil {
		viewers = append(viewers, &IPv4{passive.IPv4})
		hexdump.IPv4 = passive.IPv4
	}
	if passive.IPv6 != nil {
		viewers = append(viewers, &IPv6{passive.IPv6})
		hexdump.IPv6 = passive.IPv6
	}
	if passive.ICMP != nil {
		viewers = append(viewers, &ICMP{passive.ICMP})
		hexdump.ICMP = passive.ICMP
	}
	if passive.TCP != nil {
		viewers = append(viewers, &TCP{passive.TCP})
		hexdump.TCP = passive.TCP
	}
	if passive.UDP != nil {
		viewers = append(viewers, &UDP{passive.UDP})
		hexdump.UDP = passive.UDP
	}

	// TODO: どうにかしたい. TLS でまとめたい
	if passive.TLSClientHello != nil {
		viewers = append(viewers, &TLSv1_2_CLIENT_HELLO{passive.TLSClientHello})
		hexdump.TLSClientHello = passive.TLSClientHello
	}
	if passive.TLSServerHello != nil {
		viewers = append(viewers, &TLSv1_2_SERVER_HELLO{passive.TLSServerHello})
		hexdump.TLSServerHello = passive.TLSServerHello
	}
	if passive.TLSClientKeyExchange != nil {
		viewers = append(viewers, &TLSv1_2_ClientKeyExchange{passive.TLSClientKeyExchange})
		hexdump.TLSClientKeyExchange = passive.TLSClientKeyExchange
	}

	if passive.DNS != nil {
		viewers = append(viewers, &DNS{passive.DNS})
		hexdump.DNS = passive.DNS
	}
	if passive.HTTP != nil {
		viewers = append(viewers, &HTTP{passive.HTTP})
		hexdump.HTTP = passive.HTTP
	}
	if passive.HTTPRes != nil {
		viewers = append(viewers, &HTTPResponse{passive.HTTPRes})
		hexdump.HTTPResponse = passive.HTTPRes
	}

	viewers = append(viewers, hexdump)

	return viewers
}

func tableCellTitle(title string) *tview.TableCell {
	return tview.NewTableCell(padding(title))
}

func tableCellContent(format string, a ...any) *tview.TableCell {
	return tview.NewTableCell(padding(fmt.Sprintf(format, a...)))
}

func padding(s string) string {
	spaces := strings.Repeat(" ", 3)
	return fmt.Sprintf("%s%s%s", spaces, s, spaces)
}

func spacer(bb []byte) string {
	ret := ""
	for i, b := range bb {
		ret += fmt.Sprintf("%02x ", b)

		// 8byte毎に、大きくスペースとる
		if (i+1)%8 == 0 {
			ret += "  "
		}
	}
	return ret
}
