package generator

import (
	"context"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// arpForm は ARP の入力フォームを返す。
// Assembler（ScratchARPAssembler）の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映され、Ethernet フレームへの連結は既存の送信経路（sendL3）が担う。
func (g *generator) arpForm() *tview.Form {
	assembler := &packemon.ScratchARPAssembler{}
	// 自機の MAC/IP・デフォルトルートの IP は起動時に DEFAULT_* に設定される（cmd/packemon/main.go, init.go）。
	// これらを初期値として注入する（デフォルトのまま Send! すれば応答が返る ARP リクエストになる）
	arpForm, collectValues := buildDynamicForm(assembler, "ARP", "This section generates ARP.", map[string]string{
		"sender_mac": DEFAULT_ARP_SENDER_MAC,
		"sender_ip":  DEFAULT_ARP_SENDER_IP,
		"target_mac": DEFAULT_ARP_TARGET_MAC,
		"target_ip":  DEFAULT_ARP_TARGET_IP,
	})

	g.sender.registerApplyForm("ARP", func() error {
		arp, err := assembler.AssembleARP(collectValues())
		if err != nil {
			return err
		}
		g.sender.packets.arp = arp
		return nil
	})

	arpForm.
		AddButton("Send!", func() {
			// ARP ページからの送信は L3=ARP を明示する（Ethernet フォームの EtherType とは独立に、
			// sendL3 が Ethernet フレームの Data へ ARP を詰める既存経路に乗せる）
			g.sender.selectedProtocolByLayer["L3"] = "ARP"
			if err := g.sender.sendLayer3(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return arpForm
}
