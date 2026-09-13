package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// dnsForm は DNS の入力フォームを返す。
// Assembler（ScratchDNSAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、下位レイヤ連結は既存の送信経路（sendL7）が担う。
func (g *generator) dnsForm() *tview.Form {
	assembler := &packemon.ScratchDNSAssembler{}
	dnsForm, collectValues := buildDynamicForm(assembler, "DNS", "This section generates DNS.", nil)

	g.sender.registerApplyForm("DNS", func() error {
		dns, err := assembler.AssembleDNS(collectValues())
		if err != nil {
			return err
		}
		g.sender.packets.dns = dns
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
