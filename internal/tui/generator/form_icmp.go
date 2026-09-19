package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcICMPv4Checksum = true
var checkedCalcICMPv4Timestamp = false

// icmpForm は ICMPv4 の入力フォームを返す。
// Assembler の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、L3連結・checksum計算は既存の送信経路（sendL4）が担う。
func (g *generator) icmpForm() *tview.Form {
	// Assembler インターフェースにのみ依存する（バックエンド差し替え可能）
	var assembler packemon.Assembler = &packemon.ScratchICMPv4Assembler{}
	icmpForm, collectValues := buildDynamicForm(assembler, "ICMPv4", "This section generates ICMPv4.", nil)

	g.sender.registerApplyForm("ICMPv4", func() error {
		values := collectValues()
		// sender.packets は構造体を保持するため、Assembler が返すバイト列をパースして
		// 構造体へ戻す（バックエンドに依らず共通の変換。往復のロスレス性は
		// TestAssembleThenParseRoundtrip_allProtocols で保証）。
		// calc フラグ有効時は Assemble が payload=nil 前提の計算値を焼き込むが、
		// 送信時に下のフラグ転記に基づき既存経路が再計算するため送信パケットは変わらない
		b, err := assembler.Assemble(values, nil)
		if err != nil {
			return err
		}
		// checksum の自動計算は送信時に既存経路（sendL4）が行うため、フラグへ転記する
		calc, err := boolFromValues(values, "calc_checksum")
		if err != nil {
			return err
		}
		checkedCalcICMPv4Checksum = calc
		g.sender.packets.icmpv4 = packemon.ParsedICMPv4(b)
		return nil
	})

	icmpForm.
		AddCheckbox("Automatically add timestamp ?", checkedCalcICMPv4Timestamp, func(checked bool) {
			checkedCalcICMPv4Timestamp = checked
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
