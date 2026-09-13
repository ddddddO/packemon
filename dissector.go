package packemon

import (
	"fmt"
)

// Dissector は、受信した生バイト列をフィールドツリーへ分解するバックエンドの抽象。
// Monitor の詳細表示は、この抽象を通すことで実装（scratch / gopacket / tshark 等）を
// 差し替えられるようにする。
// 実装の命名は「実装方式 + Dissector」とする（例: ScratchDissector、将来の
// GopacketDissector / TsharkDissector）。
type Dissector interface {
	Dissect(raw []byte) (*FieldTree, error)
}

// FieldTree は1パケット分の解析結果。プロトコルごとのノードが下位層から順に並ぶ。
type FieldTree struct {
	Nodes []*FieldNode
}

// FieldNode はプロトコル、またはプロトコル内の1フィールドを表す。
// Value は表示用の文字列表現（数値の元表現には各バックエンドが責任を持つ）。
type FieldNode struct {
	Name     string
	Value    string
	Children []*FieldNode
}

// ScratchDissector は、既存のフルスクラッチ実装（ParsedPacket）による Dissector。
// 各プロトコルの FieldNode への変換は、各プロトコル構造体の FieldNode メソッド
// （各プロトコルのファイルに定義。例: ethernet.go の (*EthernetFrame).FieldNode）が担う。
type ScratchDissector struct{}

var _ Dissector = (*ScratchDissector)(nil)

func (d *ScratchDissector) Dissect(raw []byte) (ft *FieldTree, err error) {
	// ParsedPacket は短いフレーム等で panic し得る（内部でも recover している）ため、
	// バックエンド境界でエラーへ変換する
	defer func() {
		if e := recover(); e != nil {
			ft = nil
			err = fmt.Errorf("scratch dissector: %v", e)
		}
	}()

	passive := ParsedPacket(raw, true)
	if passive == nil {
		return nil, fmt.Errorf("scratch dissector: failed to parse")
	}

	return passiveToFieldTree(passive), nil
}

func passiveToFieldTree(p *Passive) *FieldTree {
	ft := &FieldTree{}

	if p.EthernetFrame != nil {
		ft.Nodes = append(ft.Nodes, p.EthernetFrame.FieldNode())
	}
	if p.ARP != nil {
		ft.Nodes = append(ft.Nodes, p.ARP.FieldNode())
	}
	if p.IPv4 != nil {
		ft.Nodes = append(ft.Nodes, p.IPv4.FieldNode())
	}
	if p.IPv6 != nil {
		ft.Nodes = append(ft.Nodes, p.IPv6.FieldNode())
	}
	if p.ICMP != nil {
		ft.Nodes = append(ft.Nodes, p.ICMP.FieldNode())
	}
	if p.TCP != nil {
		ft.Nodes = append(ft.Nodes, p.TCP.FieldNode())
	}
	if p.UDP != nil {
		ft.Nodes = append(ft.Nodes, p.UDP.FieldNode())
	}
	if p.DNS != nil {
		ft.Nodes = append(ft.Nodes, &FieldNode{Name: "DNS"}) // TODO: 詳細フィールド
	}
	// TODO: TLS 各メッセージ / HTTP の詳細フィールド
	if p.TLSClientHello != nil || p.TLSServerHello != nil || p.TLSServerHelloFor1_3 != nil ||
		p.TLSClientKeyExchange != nil || p.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil ||
		p.TLSApplicationData != nil || p.TLSEncryptedAlert != nil {
		ft.Nodes = append(ft.Nodes, &FieldNode{Name: "TLS"})
	}
	if p.HTTP != nil || p.HTTPRes != nil {
		ft.Nodes = append(ft.Nodes, &FieldNode{Name: "HTTP"})
	}

	return ft
}
