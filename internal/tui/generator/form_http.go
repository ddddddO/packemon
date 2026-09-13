package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// httpForm は HTTP の入力フォームを返す。
// Assembler（ScratchHTTPAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、下位レイヤ連結は既存の送信経路（sendL7）が担う。
func (g *generator) httpForm(ctx context.Context) *tview.Form {
	assembler := &packemon.ScratchHTTPAssembler{}
	httpForm, collectValues := buildDynamicForm(assembler, "HTTP", "This section generates HTTP.", nil)

	g.sender.registerApplyForm("HTTP", func() error {
		http, err := assembler.AssembleHTTP(collectValues())
		if err != nil {
			return err
		}
		g.sender.packets.http = http
		return nil
	})

	httpForm.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer7(ctx); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return httpForm
}
