package packemon

import (
	"fmt"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

// GopacketDissector は、gopacket による Dissector。
// 現状は Ethernet / ARP を詳細フィールドまで分解する（実装方式の比較・検証用の最初のバックエンド）。
// 各プロトコルの表示ツリー化（gopacketXxxFieldNode）は各プロトコルのファイル（ethernet.go 等）に置く。
// gopacket が認識したその他のレイヤは、レイヤ名のみのノードとして返す。
type GopacketDissector struct{}

var _ Dissector = (*GopacketDissector)(nil)

func (d *GopacketDissector) Dissect(raw []byte) (*FieldTree, error) {
	packet := gopacket.NewPacket(raw, layers.LayerTypeEthernet, gopacket.Default)
	if err := packet.ErrorLayer(); err != nil && len(packet.Layers()) == 0 {
		return nil, fmt.Errorf("gopacket dissector: %w", err.Error())
	}

	ft := &FieldTree{}
	for _, layer := range packet.Layers() {
		switch l := layer.(type) {
		case *layers.Ethernet:
			ft.Nodes = append(ft.Nodes, gopacketEthernetFieldNode(l))
		case *layers.ARP:
			ft.Nodes = append(ft.Nodes, gopacketARPFieldNode(l))
		case *gopacket.Payload:
			// ペイロードはノードにしない（hexダンプ等は別枠の責務）
		default:
			// TODO: 他レイヤの詳細フィールド化。まずはレイヤ名のみ
			ft.Nodes = append(ft.Nodes, &FieldNode{Name: layer.LayerType().String()})
		}
	}
	if packet.ErrorLayer() != nil {
		// 途中まで分解できた場合は fail-soft（分解できた層 + 失敗情報を返す）
		ft.Nodes = append(ft.Nodes, &FieldNode{
			Name:  "Dissect Error",
			Value: packet.ErrorLayer().Error().Error(),
		})
	}
	return ft, nil
}
