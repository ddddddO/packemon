package monitor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/ddddddO/packemon"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
	"github.com/rivo/tview"
)

func (m *monitor) savingPCAPView(p *packemon.Passive) *tview.Form {
	now := time.Now()
	fpath := fmt.Sprintf("./packemon_pcap/%s.pcapng", now.Format("20060102150405"))
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

		// 以降でエラーあったら、↑で生成したファイル削除がいいかも
		// ref: この辺りを参照. https://github.com/gopacket/gopacket/blob/de38b3ed5f55a68c3e7cdf34809dac42bf41d22a/pcapgo/ngwrite.go#L37
		ngwIntf := pcapgo.NgInterface{
			Name:                m.networkInterface.Intf.Name,
			LinkType:            layers.LinkTypeEthernet,
			OS:                  runtime.GOOS,
			SnapLength:          0, //unlimited
			TimestampResolution: 9,
		}
		pcapw, err := pcapgo.NewNgWriterInterface(f, ngwIntf, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			return err
		}
		defer pcapw.Flush()

		length := len(p.EthernetFrame.Data) + 14 // 14は ethernet header分
		ci := gopacket.CaptureInfo{
			Timestamp:     now,
			CaptureLength: length,
			Length:        length,
			// InterfaceIndex: intf.Index, // 必須ではなさそう. そもそもこういう事象がある: https://x.com/ddddddOpppppp/status/1893838539881631829
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
				m.addErrPage(err)
			}
		})
	form.SetBorder(true)
	form.Box = tview.NewBox().SetBorder(true).SetTitle(" Save pcapng file ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	return form
}
