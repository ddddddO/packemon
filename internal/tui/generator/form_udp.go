package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcUDPLength = true
var checkedCalcUDPChecksum = true

// udpForm は UDP の入力フォームを返す。
// Assembler（ScratchUDPAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、L3連結・checksum計算は既存の送信経路（sendL4）が担う。
func (g *generator) udpForm() *tview.Form {
	assembler := &packemon.ScratchUDPAssembler{}
	udpForm, collectValues := buildDynamicForm(assembler, "UDP", "This section generates UDP.", nil)

	g.sender.registerApplyForm("UDP", func() error {
		values := collectValues()
		udp, err := assembler.AssembleUDP(values)
		if err != nil {
			return err
		}
		// length の自動計算は送信時に既存経路（sendL4）が行うため、フラグへ転記する
		calc, err := boolFromValues(values, "calc_length")
		if err != nil {
			return err
		}
		checkedCalcUDPLength = calc
		g.sender.packets.udp = udp
		return nil
	})

	udpForm.
		AddCheckbox("Automatically calculate checksum ?", checkedCalcUDPChecksum, func(checked bool) {
			checkedCalcUDPChecksum = checked
		}).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer4(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return udpForm
}
