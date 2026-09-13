package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var doTCP3wayHandshake = false
var checkedCalcTCPChecksum = true

// tcpForm は TCP の入力フォームを返す。
// Assembler の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、L3連結・checksum計算・3way handshake は既存の送信経路が担う。
func (g *generator) tcpForm() *tview.Form {
	// Assembler インターフェースにのみ依存する（バックエンド差し替え可能）
	var assembler packemon.Assembler = &packemon.ScratchTCPAssembler{}
	tcpForm, collectValues := buildDynamicForm(assembler, "TCP", "This section generates TCP.", nil)

	g.sender.registerApplyForm("TCP", func() error {
		// sender.packets は構造体を保持するため、Assembler が返すバイト列をパースして
		// 構造体へ戻す（バックエンドに依らず共通の変換。往復のロスレス性は
		// TestAssembleThenParseRoundtrip_allProtocols で保証）
		b, err := assembler.Assemble(collectValues(), nil)
		if err != nil {
			return err
		}
		g.sender.packets.tcp = packemon.ParsedTCP(b)
		return nil
	})

	tcpForm.
		AddCheckbox("Do TCP 3way handshake ?", doTCP3wayHandshake, func(checked bool) {
			doTCP3wayHandshake = checked
		}).
		AddCheckbox("Automatically calculate checksum ?", checkedCalcTCPChecksum, func(checked bool) {
			checkedCalcTCPChecksum = checked
		}).
		AddButton("Send!", func() {
			if err := g.sender.sendLayer4(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return tcpForm
}
