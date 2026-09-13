package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPChecksum = true
var checkedCalcICMPTimestamp = false

// icmpForm は ICMP の入力フォームを返す。
// Assembler（ScratchICMPAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、L3連結・checksum計算は既存の送信経路（sendL4）が担う。
func (g *generator) icmpForm() *tview.Form {
	assembler := &packemon.ScratchICMPAssembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMP", "This section generates ICMP.", nil)

	g.sender.registerApplyForm("ICMP", func() error {
		values := collectValues()
		icmp, err := assembler.AssembleICMP(values)
		if err != nil {
			return err
		}
		// checksum の自動計算は送信時に既存経路（sendL4）が行うため、フラグへ転記する
		calc, err := boolFromValues(values, "calc_checksum")
		if err != nil {
			return err
		}
		checkedCalcICMPChecksum = calc
		g.sender.packets.icmpv4 = icmp
		return nil
	})

	icmpForm.
		AddCheckbox("Automatically add timestamp ?", checkedCalcICMPTimestamp, func(checked bool) {
			checkedCalcICMPTimestamp = checked
		}).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer4(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return icmpForm
}
