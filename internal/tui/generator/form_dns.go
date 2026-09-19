package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// dnsForm は DNS の入力フォームを返す。
// Assembler の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、下位レイヤ連結は既存の送信経路（sendL7）が担う。
func (g *generator) dnsForm() *tview.Form {
	// Assembler インターフェースにのみ依存する（バックエンド差し替え可能）
	var assembler packemon.Assembler = &packemon.ScratchDNSAssembler{}
	dnsForm, collectValues := buildDynamicForm(assembler, "DNS", "This section generates DNS.", nil)

	g.sender.registerApplyForm("DNS", func() error {
		// sender.packets は構造体を保持するため、Assembler が返すバイト列をパースして
		// 構造体へ戻す（バックエンドに依らず共通の変換。往復のロスレス性は
		// TestAssembleThenParseRoundtrip_allProtocols で保証）
		b, err := assembler.Assemble(collectValues(), nil)
		if err != nil {
			return err
		}
		g.sender.packets.dns = packemon.ParsedDNSRequest(b)
		return nil
	})

	dnsForm.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer7(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return dnsForm
}
