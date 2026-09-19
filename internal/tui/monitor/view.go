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

		packetDetail := tview.NewFlex().SetDirection(tview.FlexRow)

		m.app.QueueUpdate(func() {
			packetDetail.Clear()
		})

		for i := range viewers {
			packetDetail.AddItem(viewers[i].viewTable(), 0, 1, false)
		}
		savingPCAPView := m.savingPCAPView(passive)
		packetDetail.AddItem(savingPCAPView, 0, 1, false)

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
	// FieldNode を実装するプロトコルは汎用レンダラ（FieldNodeView）で表示する。
	// 表示フィールドの定義は各プロトコルの FieldNode メソッド（例: ethernet.go）に一元化されている
	if passive.EthernetFrame != nil {
		viewers = append(viewers, &FieldNodeView{passive.EthernetFrame.FieldNode()})
		hexdump.EthernetFrame = passive.EthernetFrame
	}
	if passive.ARP != nil {
		viewers = append(viewers, &FieldNodeView{passive.ARP.FieldNode()})
		hexdump.ARP = passive.ARP
	}
	if passive.IPv4 != nil {
		viewers = append(viewers, &FieldNodeView{passive.IPv4.FieldNode()})
		hexdump.IPv4 = passive.IPv4
	}
	if passive.IPv6 != nil {
		viewers = append(viewers, &FieldNodeView{passive.IPv6.FieldNode()})
		hexdump.IPv6 = passive.IPv6
	}
	if passive.ICMP != nil {
		viewers = append(viewers, &FieldNodeView{passive.ICMP.FieldNode()})
		hexdump.ICMP = passive.ICMP
	}
	if passive.TCP != nil {
		viewers = append(viewers, &FieldNodeView{passive.TCP.FieldNode()})
		hexdump.TCP = passive.TCP
	}
	if passive.UDP != nil {
		viewers = append(viewers, &FieldNodeView{passive.UDP.FieldNode()})
		hexdump.UDP = passive.UDP
	}

	if passive.TLSClientHello != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSClientHello.FieldNode()})
		hexdump.TLSClientHello = passive.TLSClientHello
	}
	if passive.TLSServerHello != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSServerHello.FieldNode()})
		hexdump.TLSServerHello = passive.TLSServerHello
	}
	if passive.TLSServerHelloFor1_3 != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSServerHelloFor1_3.FieldNode()})
		hexdump.TLSServerHelloFor1_3 = passive.TLSServerHelloFor1_3
	}
	if passive.TLSClientKeyExchange != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSClientKeyExchange.FieldNode()})
		hexdump.TLSClientKeyExchange = passive.TLSClientKeyExchange
	}
	if passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage.FieldNode()})
		hexdump.TLSChangeCipherSpecAndEncryptedHandshakeMessage = passive.TLSChangeCipherSpecAndEncryptedHandshakeMessage
	}
	if passive.TLSApplicationData != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSApplicationData.FieldNode()})
		hexdump.TLSApplicationData = passive.TLSApplicationData
	}
	if passive.TLSEncryptedAlert != nil {
		viewers = append(viewers, &FieldNodeView{passive.TLSEncryptedAlert.FieldNode()})
		hexdump.TLSEncryptedAlert = passive.TLSEncryptedAlert
	}

	if passive.DNS != nil {
		viewers = append(viewers, &FieldNodeView{passive.DNS.FieldNode()})
		hexdump.DNS = passive.DNS
	}
	if passive.HTTP != nil {
		viewers = append(viewers, &FieldNodeView{passive.HTTP.FieldNode()})
		hexdump.HTTP = passive.HTTP
	}
	if passive.HTTPRes != nil {
		viewers = append(viewers, &FieldNodeView{passive.HTTPRes.FieldNode()})
		hexdump.HTTPResponse = passive.HTTPRes
	}

	viewers = append(viewers, hexdump)

	return viewers
}

// 2byteをintへ変換
func bytesToInt(b []byte) int {
	return int(b[0])<<8 + int(b[1])
}
