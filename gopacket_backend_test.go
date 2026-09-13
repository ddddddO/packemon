package packemon

import (
	"bytes"
	"reflect"
	"testing"
)

// scratch 版と gopacket 版の Assembler が「同じ values から同一のバイト列」を生成することの突き合わせ。
// バックエンドを差し替えても送信されるパケットが変わらないことの保証（相互検証にもなる）。
func TestAssemblerBackendsProduceSameBytes_ethernet(t *testing.T) {
	values := map[string]any{
		"dst":        "00:15:5d:e2:c6:c6",
		"src":        "00:15:5d:6f:44:33",
		"ether_type": "IPv4",
	}
	payload := []byte{0xde, 0xad, 0xbe, 0xef}

	scratch, err := (&ScratchEthernetAssembler{}).Assemble(values, payload)
	if err != nil {
		t.Fatalf("scratch: %v", err)
	}
	gp, err := (&GopacketEthernetAssembler{}).Assemble(values, payload)
	if err != nil {
		t.Fatalf("gopacket: %v", err)
	}

	if !bytes.Equal(scratch, gp) {
		t.Fatalf("backend mismatch\nscratch : %x\ngopacket: %x", scratch, gp)
	}
}

func TestAssemblerBackendsProduceSameBytes_arp(t *testing.T) {
	values := map[string]any{
		"hardware_type": "0x0001",
		"protocol_type": "0x0800",
		"hardware_size": "0x06",
		"protocol_size": "0x04",
		"operation":     "0x0001",
		"sender_mac":    "00:15:5d:6f:44:33",
		"sender_ip":     "192.168.10.5",
		"target_mac":    "00:00:00:00:00:00",
		"target_ip":     "192.168.10.1",
	}

	scratch, err := (&ScratchARPAssembler{}).Assemble(values, nil)
	if err != nil {
		t.Fatalf("scratch: %v", err)
	}
	gp, err := (&GopacketARPAssembler{}).Assemble(values, nil)
	if err != nil {
		t.Fatalf("gopacket: %v", err)
	}

	if !bytes.Equal(scratch, gp) {
		t.Fatalf("backend mismatch\nscratch : %x\ngopacket: %x", scratch, gp)
	}
}

// scratch 版 Assembler の出力を gopacket 版 Dissector で分解して値が一致すること（クロス検証）。
func TestGopacketDissector_Dissect(t *testing.T) {
	ethValues := map[string]any{
		"dst":        "ff:ff:ff:ff:ff:ff",
		"src":        "00:15:5d:6f:44:33",
		"ether_type": "ARP",
	}
	arpValues := map[string]any{
		"hardware_type": "0x0001",
		"protocol_type": "0x0800",
		"hardware_size": "0x06",
		"protocol_size": "0x04",
		"operation":     "0x0001",
		"sender_mac":    "00:15:5d:6f:44:33",
		"sender_ip":     "192.168.10.5",
		"target_mac":    "00:00:00:00:00:00",
		"target_ip":     "192.168.10.1",
	}
	arpBytes, err := (&ScratchARPAssembler{}).Assemble(arpValues, nil)
	if err != nil {
		t.Fatalf("assemble arp: %v", err)
	}
	frame, err := (&ScratchEthernetAssembler{}).Assemble(ethValues, arpBytes)
	if err != nil {
		t.Fatalf("assemble ethernet: %v", err)
	}

	ft, err := (&GopacketDissector{}).Dissect(frame)
	if err != nil {
		t.Fatalf("dissect: %v", err)
	}

	nodeByName := map[string]*FieldNode{}
	for _, n := range ft.Nodes {
		nodeByName[n.Name] = n
	}

	eth, ok := nodeByName["Ethernet"]
	if !ok {
		t.Fatalf("Ethernet node not found: %+v", ft.Nodes)
	}
	assertChildValue(t, eth, "Source", "00:15:5d:6f:44:33")

	arp, ok := nodeByName["ARP"]
	if !ok {
		t.Fatalf("ARP node not found: %+v", ft.Nodes)
	}
	assertChildValue(t, arp, "Operation Code", "0x0001")
	assertChildValue(t, arp, "Sender IP Addr", "192.168.10.5")
	assertChildValue(t, arp, "Target IP Addr", "192.168.10.1")
}

// scratch 版 Dissector と gopacket 版 Dissector が同じフレームから同じ主要フィールド値を得ること。
func TestDissectorBackendsAgree_arp(t *testing.T) {
	arp := &ARP{
		HardwareType: 0x0001, ProtocolType: 0x0800,
		HardwareAddrLength: 6, ProtocolLength: 4, Operation: 0x0002,
		SenderHardwareAddr: HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		SenderIPAddr:       0xc0a80a01,
		TargetHardwareAddr: HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		TargetIPAddr:       0xc0a80a05,
	}
	frame := NewEthernetFrame(
		HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		ETHER_TYPE_ARP,
		arp.Bytes(),
	)

	scratchFT, err := (&ScratchDissector{}).Dissect(frame.Bytes())
	if err != nil {
		t.Fatalf("scratch dissect: %v", err)
	}
	gpFT, err := (&GopacketDissector{}).Dissect(frame.Bytes())
	if err != nil {
		t.Fatalf("gopacket dissect: %v", err)
	}

	for _, name := range []string{"Sender IP Addr", "Target IP Addr", "Sender Mac Addr", "Operation Code"} {
		s := findNodeChildValue(t, scratchFT, "ARP", name)
		g := findNodeChildValue(t, gpFT, "ARP", name)
		if s != g {
			t.Fatalf("%s: scratch=%q gopacket=%q", name, s, g)
		}
	}
}

func findNodeChildValue(t *testing.T, ft *FieldTree, nodeName, childName string) string {
	t.Helper()
	for _, n := range ft.Nodes {
		if n.Name != nodeName {
			continue
		}
		for _, c := range n.Children {
			if c.Name == childName {
				return c.Value
			}
		}
	}
	t.Fatalf("%s/%s not found", nodeName, childName)
	return ""
}

// フォームの apply が「構造体返却の固有メソッド（AssembleARP 等）」から
// 「インターフェースの Assemble → Parsed* で構造体へ」に変わっても、
// sender.packets に入る構造体が同一であることの保証（往復がロスレスであることの回帰テスト）。
func TestAssembleThenParseRoundtrip_arp(t *testing.T) {
	values := map[string]any{
		"hardware_type": "0x0001",
		"protocol_type": "0x0800",
		"hardware_size": "0x06",
		"protocol_size": "0x04",
		"operation":     "0x0002",
		"sender_mac":    "00:15:5d:6f:44:33",
		"sender_ip":     "192.168.10.5",
		"target_mac":    "00:15:5d:e2:c6:c6",
		"target_ip":     "192.168.10.1",
	}
	scratch := &ScratchARPAssembler{}

	// 旧経路: 構造体を直接得る
	want, err := scratch.AssembleARP(values)
	if err != nil {
		t.Fatalf("AssembleARP: %v", err)
	}

	// 新経路: バイト列を経由して構造体へ戻す（両バックエンドで）
	for name, assembler := range map[string]Assembler{"scratch": scratch, "gopacket": &GopacketARPAssembler{}} {
		b, err := assembler.Assemble(values, nil)
		if err != nil {
			t.Fatalf("%s Assemble: %v", name, err)
		}
		got := ParsedARP(b)
		if !reflect.DeepEqual(want, got) {
			t.Fatalf("%s: roundtrip mismatch\nwant: %+v\ngot : %+v", name, want, got)
		}
	}
}

func TestAssembleThenParseRoundtrip_ethernet(t *testing.T) {
	scratch := &ScratchEthernetAssembler{}

	t.Run("通常のEtherType", func(t *testing.T) {
		values := map[string]any{
			"dst":        "00:15:5d:e2:c6:c6",
			"src":        "00:15:5d:6f:44:33",
			"ether_type": "IPv4",
		}
		want, err := scratch.AssembleEthernetHeader(values)
		if err != nil {
			t.Fatalf("AssembleEthernetHeader: %v", err)
		}
		for name, assembler := range map[string]Assembler{"scratch": scratch, "gopacket": &GopacketEthernetAssembler{}} {
			b, err := assembler.Assemble(values, nil)
			if err != nil {
				t.Fatalf("%s Assemble: %v", name, err)
			}
			got := ParsedEthernetFrame(b).Header
			// 旧経路は Typ に依らず Dot1QFiels へデフォルト値を入れるが、新経路は
			// DOT1Q 以外では nil。参照箇所はすべて Typ == DOT1Q ガード付きのため実害なし
			// （ethernet.go の Bytes / FieldNode を参照）。ここでは実送信に影響する
			// Dst/Src/Typ の一致を確認する
			if got.Dst != want.Dst || got.Src != want.Src || got.Typ != want.Typ {
				t.Fatalf("%s: roundtrip mismatch\nwant: %+v\ngot : %+v", name, want, got)
			}
		}
	})

	t.Run("DOT1Q", func(t *testing.T) {
		values := map[string]any{
			"dst":          "00:15:5d:e2:c6:c6",
			"src":          "00:15:5d:6f:44:33",
			"ether_type":   "Dot1Q",
			"dot1q_fields": "0x2064", // PCP=1, VLAN=100
			"dot1q_type":   "0x0800",
		}
		want, err := scratch.AssembleEthernetHeader(values)
		if err != nil {
			t.Fatalf("AssembleEthernetHeader: %v", err)
		}
		for name, assembler := range map[string]Assembler{"scratch": scratch, "gopacket": &GopacketEthernetAssembler{}} {
			b, err := assembler.Assemble(values, nil)
			if err != nil {
				t.Fatalf("%s Assemble: %v", name, err)
			}
			got := ParsedEthernetFrame(b).Header
			// DOT1Q のときは Dot1QFiels 含め完全一致すること（送信バイト列に直接影響するため）
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("%s: roundtrip mismatch\nwant: %+v (dot1q %+v)\ngot : %+v (dot1q %+v)", name, want, want.Dot1QFiels, got, got.Dot1QFiels)
			}
		}
	})
}
