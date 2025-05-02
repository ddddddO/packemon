package monitor

import (
	"fmt"
	"runtime/debug"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

func (m *monitor) updateView(passive *packemon.Passive) {
	go func(viewers []Viewer) {
		defer func() {
			if e := recover(); e != nil {
				trace := debug.Stack()
				err := fmt.Errorf("Panic!!\n%v\nstack trace\n%s\n", e, string(trace))
				m.addErrPage(err)
			}
		}()

		packetDetail := tview.NewGrid()

		m.app.QueueUpdate(func() {
			packetDetail.Clear()
		})

		// m.grid.RemoveItem(m.grid) // ほんと？

		// +1 分は、PCAP保存領域用(savingPCAPView)
		rows := make([]int, len(viewers)+1)
		columns := make([]int, len(viewers)+1)
		for i := range viewers {
			rows[i] = viewers[i].rows()
			columns[i] = viewers[i].columns()
		}

		// SetRows しなくなったので、各テーブルの rows メソッドいらないかも
		// t.grid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
		packetDetail.SetColumns(columns...).SetBorders(false)

		for i := range viewers {
			packetDetail.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false) // focus=true にするとスクロールしない
		}
		savingPCAPView := m.savingPCAPView(passive)
		row := len(viewers)
		packetDetail.AddItem(savingPCAPView, row, 0, 1, 3, 0, 0, false)

		packetDetail.SetInputCapture(
			func(event *tcell.EventKey) *tcell.EventKey {
				if event.Key() == tcell.KeyEscape {
					packetDetail.Clear()

					m.grid.AddItem(m.filterInput, 0, 0, 1, 1, 0, 0, false) // TODO: tui.go のと共通化する
					m.app.SetRoot(m.grid, true)
					m.app.SetFocus(m.grid)
				}
				return event
			})

		grid := tview.NewGrid()
		grid.Box = tview.NewBox().SetTitle(tui.TITLE_MONITOR).SetBorder(true)
		grid.AddItem(packetDetail, 0, 0, 1, 1, 1, 1, true)
		m.app.SetRoot(grid, true)
		m.app.Draw()
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
	if passive.TLSServerHelloFor1_3 != nil {
		viewers = append(viewers, &TLSv1_3_SERVER_HELLO{passive.TLSServerHelloFor1_3})
		hexdump.TLSServerHelloFor1_3 = passive.TLSServerHelloFor1_3
	}
	if passive.TLSClientKeyExchange != nil {
		viewers = append(viewers, &TLSv1_2_ClientKeyExchange{passive.TLSClientKeyExchange})
		hexdump.TLSClientKeyExchange = passive.TLSClientKeyExchange
	}
	if passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil {
		viewers = append(viewers, &TLSv1_2_ChangeCipherSpecAndEncryptedHandshakeMessage{passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage})
		hexdump.TLSChangeCipherSpecAndEncryptedHandshakeMessage = passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage
	}
	if passive.TLSApplicationData != nil {
		viewers = append(viewers, &TLSv1_2_ApplicationData{passive.TLSApplicationData})
		hexdump.TLSApplicationData = passive.TLSApplicationData
	}
	if passive.TLSEncryptedAlert != nil {
		viewers = append(viewers, &TLSv1_2_EncryptedAlert{passive.TLSEncryptedAlert})
		hexdump.TLSEncryptedAlert = passive.TLSEncryptedAlert
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

// 2byteをintへ変換
func bytesToInt(b []byte) int {
	return int(b[0])<<8 + int(b[1])
}
