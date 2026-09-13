package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

var doTCP3wayHandshake = false
var checkedCalcTCPChecksum = true

// tcpForm は TCP の入力フォームを返す。
// Assembler（ScratchTCPAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、L3連結・checksum計算・3way handshake は既存の送信経路が担う。
func (g *generator) tcpForm() *tview.Form {
	assembler := &packemon.ScratchTCPAssembler{}
	tcpForm, collectValues := buildDynamicForm(assembler, "TCP", "This section generates TCP.", nil)

	g.sender.registerApplyForm("TCP", func() error {
		tcp, err := assembler.AssembleTCP(collectValues())
		if err != nil {
			return err
		}
		g.sender.packets.tcp = tcp
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
