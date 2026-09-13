package monitor

import (
	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

// FieldNodeView は、FieldNode（Dissector バックエンドの解析結果）を表示する汎用 Viewer。
// プロトコルごとに viewTable を手書きしていた view_*.go の置き換え。
// FieldNode を実装するプロトコルはこの1つのレンダラで詳細表示でき、
// フィールドの追加・修正は各プロトコルの FieldNode メソッド側だけで済む。
type FieldNodeView struct {
	node *packemon.FieldNode
}

func (v *FieldNodeView) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" "+v.node.Name+" ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	row := 0
	var addNodes func(nodes []*packemon.FieldNode, indent string)
	addNodes = func(nodes []*packemon.FieldNode, indent string) {
		for _, n := range nodes {
			table.SetCell(row, 0, tui.TableCellTitle(indent+n.Name))
			if n.Value != "" {
				table.SetCell(row, 1, tui.TableCellContent("%s", n.Value))
			}
			row++
			// 入れ子（DNS の Answer 等）はインデントして表示する
			addNodes(n.Children, indent+"   ")
		}
	}
	addNodes(v.node.Children, "")

	return table
}
