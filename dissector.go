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

	return FieldTreeFromPassive(passive), nil
}

// FieldTreeFromPassive は、スクラッチ実装のパース結果（Passive）を FieldTree へ変換する。
// Monitor の詳細表示は、パース済みの Passive を保持しているためこの関数を直接使う
// （raw バイト列からの分解は ScratchDissector.Dissect を使う）。
func FieldTreeFromPassive(p *Passive) *FieldTree {
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
	if p.ICMPv4EchoOrEchoReply != nil {
		ft.Nodes = append(ft.Nodes, p.ICMPv4EchoOrEchoReply.FieldNode())
	}
	if p.TCP != nil {
		ft.Nodes = append(ft.Nodes, p.TCP.FieldNode())
	}
	if p.UDP != nil {
		ft.Nodes = append(ft.Nodes, p.UDP.FieldNode())
	}
	if p.TLSClientHello != nil {
		ft.Nodes = append(ft.Nodes, p.TLSClientHello.FieldNode())
	}
	if p.TLSServerHello != nil {
		ft.Nodes = append(ft.Nodes, p.TLSServerHello.FieldNode())
	}
	if p.TLSServerHelloFor1_3 != nil {
		ft.Nodes = append(ft.Nodes, p.TLSServerHelloFor1_3.FieldNode())
	}
	if p.TLSClientKeyExchange != nil {
		ft.Nodes = append(ft.Nodes, p.TLSClientKeyExchange.FieldNode())
	}
	if p.TLSChangeCipherSpecAndEncryptedHandshakeMessage != nil {
		ft.Nodes = append(ft.Nodes, p.TLSChangeCipherSpecAndEncryptedHandshakeMessage.FieldNode())
	}
	if p.TLSApplicationData != nil {
		ft.Nodes = append(ft.Nodes, p.TLSApplicationData.FieldNode())
	}
	if p.TLSEncryptedAlert != nil {
		ft.Nodes = append(ft.Nodes, p.TLSEncryptedAlert.FieldNode())
	}
	if p.DNS != nil {
		ft.Nodes = append(ft.Nodes, p.DNS.FieldNode())
	}
	if p.HTTP != nil {
		ft.Nodes = append(ft.Nodes, p.HTTP.FieldNode())
	}
	if p.HTTPRes != nil {
		ft.Nodes = append(ft.Nodes, p.HTTPRes.FieldNode())
	}

	return ft
}
