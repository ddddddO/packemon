package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/ddddddO/packemon"
	"github.com/gdamore/tcell/v2"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/rivo/tview"
)

type Viewer interface {
	rows() int
	columns() int
	viewTable() *tview.Table
}

func (t *tui) updateView(passive *packemon.Passive) {
	go func(viewers []Viewer) {
		defer func() {
			if e := recover(); e != nil {
				trace := debug.Stack()
				err := fmt.Errorf("Panic!!\n%v\nstack trace\n%s\n", e, string(trace))
				t.addErrPageForMonitor(err)
			}
		}()

		t.app.QueueUpdate(func() {
			t.grid.Clear()
		})

		t.grid.RemoveItem(t.grid) // ほんと？

		// +1 分は、PCAP保存領域用(savingPCAPView)
		rows := make([]int, len(viewers)+1)
		columns := make([]int, len(viewers)+1)
		rows[0] = 5
		columns[0] = 30
		for i := range viewers {
			rows[i] = viewers[i].rows()
			columns[i] = viewers[i].columns()
		}

		// SetRows しなくなったので、各テーブルの rows メソッドいらないかも
		// t.grid.SetRows(rows...).SetColumns(columns...).SetBorders(false)
		t.grid.SetColumns(columns...).SetBorders(false)

		for i := range viewers {
			t.grid.AddItem(viewers[i].viewTable(), i, 0, 1, 3, 0, 0, false) // focus=true にするとスクロールしない
		}
		savingPCAPView := t.savingPCAPView(passive)
		row := len(viewers)
		t.grid.AddItem(savingPCAPView, row, 0, 1, 3, 0, 0, false)

		t.grid.SetInputCapture(
			func(event *tcell.EventKey) *tcell.EventKey {
				if event.Key() == tcell.KeyEscape {
					t.grid.Clear()
					t.pages.SwitchToPage("history")
					t.app.SetFocus(t.pages)
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

func (t *tui) savingPCAPView(p *packemon.Passive) *tview.Form {
	now := time.Now()
	fpath := fmt.Sprintf("./packemon_pcap/%s.pcap", now.Format("20060102150405"))
	limitLength := 60
	save := func() error {
		if p.EthernetFrame == nil {
			return fmt.Errorf("Empty ethernet frame...")
		}

		dir := filepath.Dir(fpath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}

		f, err := os.Create(fpath)
		if err != nil {
			return err
		}
		defer f.Close()

		pcapw := pcapgo.NewWriter(f)
		if err := pcapw.WriteFileHeader(1500, layers.LinkTypeEthernet); err != nil {
			return err
		}
		ci := gopacket.CaptureInfo{
			Timestamp:     now,
			CaptureLength: 1500,
			Length:        1500,
			// InterfaceIndex: intf.Index, // 必須ではなさそう
		}
		return pcapw.WritePacket(ci, p.EthernetFrame.Bytes())
	}

	form := tview.NewForm().
		AddInputField("File Name", fpath, limitLength, func(textToCheck string, lastChar rune) bool {
			if len(textToCheck) < limitLength {
				fpath = textToCheck
				return true
			} else if len(textToCheck) > limitLength {
				return false
			}
			fpath = textToCheck
			return true
		}, nil).
		AddButton("Save", func() {
			if err := save(); err != nil {
				t.addErrPageForMonitor(err)
			}
		})
	form.SetBorder(true)
	form.Box = tview.NewBox().SetBorder(true).SetTitle(" Save PCAP ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	return form
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
