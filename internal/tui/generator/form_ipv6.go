package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var checkedCalcIPv6PayloadLength = true

// ipv6Form は IPv6 の入力フォームを返す。
// Assembler の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、自動計算・上位レイヤ連結は既存の送信経路が担う。
func (g *generator) ipv6Form() *tview.Form {
	// Assembler インターフェースにのみ依存する（バックエンド差し替え可能）
	var assembler packemon.Assembler = &packemon.ScratchIPv6Assembler{}
	// 自機の IP は起動時に DEFAULT_* に設定される（cmd/packemon/main.go）
	ipv6Form, collectValues := buildDynamicForm(assembler, "IPv6 Header", "This section generates the IPv6 header.", map[string]string{
		"src": DEFAULT_IPv6_SOURCE,
		"dst": DEFAULT_IPv6_DESTINATION,
	})

	g.sender.registerApplyForm("IPv6", func() error {
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
		// 自動計算は送信時に既存経路（sendL3/L4）が行うため、フラグへ転記する
		calc, err := boolFromValues(values, "calc_payload_length")
		if err != nil {
			return err
		}
		checkedCalcIPv6PayloadLength = calc

		g.sender.packets.ipv6 = packemon.ParsedIPv6(b)
		return nil
	})

	ipv6Form.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer3(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ipv6Form
}
