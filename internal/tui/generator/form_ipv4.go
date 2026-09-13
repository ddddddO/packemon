package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcIPv4TotalLength = true
var checkedCalcIPv4Checksum = true

// ipv4Form は IPv4 の入力フォームを返す。
// Assembler（ScratchIPv4Assembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、自動計算・上位レイヤ連結は既存の送信経路が担う。
func (g *generator) ipv4Form() *tview.Form {
	assembler := &packemon.ScratchIPv4Assembler{}
	// 自機の IP は起動時に DEFAULT_* に設定される（cmd/packemon/main.go）
	ipv4Form, collectValues := buildDynamicForm(assembler, "IPv4 Header", "This section generates the IPv4 header.", map[string]string{
		"src": DEFAULT_IP_SOURCE,
		"dst": DEFAULT_IP_DESTINATION,
	})

	g.sender.registerApplyForm("IPv4", func() error {
		values := collectValues()
		ipv4, err := assembler.AssembleIPv4(values)
		if err != nil {
			return err
		}
		// 自動計算は送信時に既存経路（sendL3/L4）が行うため、フラグへ転記する
		calcTotalLength, err := boolFromValues(values, "calc_total_length")
		if err != nil {
			return err
		}
		checkedCalcIPv4TotalLength = calcTotalLength
		calcChecksum, err := boolFromValues(values, "calc_checksum")
		if err != nil {
			return err
		}
		checkedCalcIPv4Checksum = calcChecksum

		g.sender.packets.ipv4 = ipv4
		return nil
	})

	ipv4Form.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer3(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ipv4Form
}
