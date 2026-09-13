package generator

import (
	"context"
	"testing"

	"github.com/ddddddO/packemon"
)

func TestBuildDynamicForm_ARP(t *testing.T) {
	assembler := &packemon.ScratchARPAssembler{}

	form, collectValues := buildDynamicForm(assembler, "ARP", "This section generates ARP.", nil)

	// 先頭の TextView + Fields 数ぶんのフォーム項目が生成されること
	wantCount := 1 + len(assembler.Fields())
	if got := form.GetFormItemCount(); got != wantCount {
		t.Fatalf("form item count: got %d, want %d", got, wantCount)
	}

	// デフォルト値のまま収集した values で Assemble が成功すること
	// （FieldSpec の Default が Assembler 自身の受け付ける形式と整合している保証になる）
	values := collectValues()
	if _, err := assembler.Assemble(values, nil); err != nil {
		t.Fatalf("assemble with default values: %v", err)
	}
}

func TestBuildDynamicForm_IPv4_checkboxAndDefaults(t *testing.T) {
	assembler := &packemon.ScratchIPv4Assembler{}

	_, collectValues := buildDynamicForm(assembler, "IPv4", "This section generates IPv4 header.", nil)

	values := collectValues()

	// チェックボックス（自動計算）のデフォルト true が bool で収集されること
	calc, ok := values["calc_checksum"].(bool)
	if !ok || !calc {
		t.Fatalf("calc_checksum: got %v", values["calc_checksum"])
	}

	// デフォルト値で Assemble が成功し、自動計算が効いていること
	payload := []byte{0x01, 0x02}
	b, err := assembler.Assemble(values, payload)
	if err != nil {
		t.Fatalf("assemble with default values: %v", err)
	}
	ip := packemon.ParsedIPv4(b)
	if int(ip.TotalLength) != 20+len(payload) {
		t.Fatalf("total length should be auto-calculated: got %d", ip.TotalLength)
	}
}

func TestBuildDynamicForm_allAssemblers(t *testing.T) {
	// 全 Assembler で「フォーム生成 → デフォルト値収集 → Assemble」が通ること
	assemblers := map[string]packemon.Assembler{
		"Ethernet": &packemon.ScratchEthernetAssembler{},
		"ARP":      &packemon.ScratchARPAssembler{},
		"IPv4":     &packemon.ScratchIPv4Assembler{},
		"IPv6":     &packemon.ScratchIPv6Assembler{},
		"ICMP":     &packemon.ScratchICMPAssembler{},
		"TCP":      &packemon.ScratchTCPAssembler{},
		"UDP":      &packemon.ScratchUDPAssembler{},
		"DNS":      &packemon.ScratchDNSAssembler{},
		"HTTP":     &packemon.ScratchHTTPAssembler{},
	}
	for name, assembler := range assemblers {
		t.Run(name, func(t *testing.T) {
			_, collectValues := buildDynamicForm(assembler, name, "", nil)
			if _, err := assembler.Assemble(collectValues(), nil); err != nil {
				t.Fatalf("assemble with default values: %v", err)
			}
		})
	}
}

func TestSendLayer3_dynamicARPForm(t *testing.T) {
	// 動的フォーム（apply登録）→ 既存送信経路（sendL3）の統合確認。
	// Ethernet フォームの apply（EtherType=ARP）が ARP 送信時にも反映されることを含む
	// （かつて ARP だけ特殊経路で apply が走らず、EtherType が IPv4 のまま送られるバグの回帰テスト）
	var sent *packemon.EthernetFrame
	s := newSender(
		&packets{
			// 初期値は EtherType=IPv4（defaultPackets 相当）。apply で ARP に上書きされることを確認する
			ethernet: &packemon.EthernetHeader{
				Dst: packemon.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
				Src: packemon.HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
				Typ: packemon.ETHER_TYPE_IPv4,
			},
		},
		func(ef *packemon.EthernetFrame) error {
			sent = ef
			return nil
		},
	)
	s.selectedProtocolByLayer["L3"] = "ARP"

	// Ethernet フォーム相当（EtherType=ARP を選択した状態）
	ethernetAssembler := &packemon.ScratchEthernetAssembler{}
	_, collectEthernet := buildDynamicForm(ethernetAssembler, "Ethernet", "", map[string]string{
		"dst":        "ff:ff:ff:ff:ff:ff",
		"src":        "00:15:5d:6f:44:33",
		"ether_type": "ARP",
	})
	s.registerApplyForm("Ethernet", func() error {
		header, err := ethernetAssembler.AssembleEthernetHeader(collectEthernet())
		if err != nil {
			return err
		}
		s.packets.ethernet = header
		return nil
	})

	// ARP フォーム相当
	arpAssembler := &packemon.ScratchARPAssembler{}
	_, collectARP := buildDynamicForm(arpAssembler, "ARP", "", nil)
	s.registerApplyForm("ARP", func() error {
		arp, err := arpAssembler.AssembleARP(collectARP())
		if err != nil {
			return err
		}
		s.packets.arp = arp
		return nil
	})

	if err := s.sendLayer3(context.Background()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if sent == nil {
		t.Fatal("sendFn was not called")
	}
	// Ethernet フォームの apply が効いて EtherType が ARP になっていること
	if sent.Header.Typ != packemon.ETHER_TYPE_ARP {
		t.Fatalf("ether type: got 0x%04x, want 0x%04x (ARP)", sent.Header.Typ, packemon.ETHER_TYPE_ARP)
	}
	// 送られた Data が ARP としてパースできること
	arp := packemon.ParsedARP(sent.Data)
	if arp.Operation != 0x0001 {
		t.Fatalf("operation: got 0x%04x", arp.Operation)
	}
}

func TestBuildDynamicForm_defaultOverrides(t *testing.T) {
	// 実行時デフォルト（自機MAC/IP等）の注入がフォーム初期値に反映されること。
	// 既存の手書きフォームの入力形式（0x プレフィックスMAC）も受理されること
	assembler := &packemon.ScratchARPAssembler{}
	_, collectValues := buildDynamicForm(assembler, "ARP", "", map[string]string{
		"sender_mac": "0x00155d6f4433",
		"sender_ip":  "192.168.10.5",
		"target_ip":  "192.168.10.1",
	})

	values := collectValues()
	if values["sender_ip"] != "192.168.10.5" {
		t.Fatalf("sender_ip: got %v", values["sender_ip"])
	}
	if values["target_ip"] != "192.168.10.1" {
		t.Fatalf("target_ip: got %v", values["target_ip"])
	}

	// 注入値のまま Assemble でき、意図した ARP リクエストになること
	b, err := assembler.Assemble(values, nil)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	arp := packemon.ParsedARP(b)
	if arp.SenderHardwareAddr.String() != "00:15:5d:6f:44:33" {
		t.Fatalf("sender mac: got %s", arp.SenderHardwareAddr.String())
	}
}

func TestSendLayer4_dynamicICMPForm(t *testing.T) {
	// 動的フォーム（apply登録）→ 既存送信経路（sendL4: L3連結・checksum計算）の統合確認
	var sent *packemon.EthernetFrame
	s := newSender(
		&packets{
			ethernet: &packemon.EthernetHeader{
				Dst: packemon.HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
				Src: packemon.HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
				Typ: packemon.ETHER_TYPE_IPv4,
			},
			ipv4: packemon.NewIPv4(packemon.IPv4_PROTO_ICMP, 0xc0a80001, 0xc0a80002),
		},
		func(ef *packemon.EthernetFrame) error {
			sent = ef
			return nil
		},
	)
	s.selectedProtocolByLayer["L4"] = "ICMP"

	assembler := &packemon.ScratchICMPAssembler{}
	_, collectValues := buildDynamicForm(assembler, "ICMP", "", nil)
	s.registerApplyForm("ICMP", func() error {
		icmp, err := assembler.AssembleICMP(collectValues())
		if err != nil {
			return err
		}
		s.packets.icmpv4 = icmp
		return nil
	})

	if err := s.sendLayer4(context.Background()); err != nil {
		t.Fatalf("send: %v", err)
	}
	if sent == nil {
		t.Fatal("sendFn was not called")
	}

	// 送信されたフレームが IPv4 + ICMP として正しいこと（checksum は既存経路で計算済み）
	ip := packemon.ParsedIPv4(sent.Data)
	if ip.Protocol != packemon.IPv4_PROTO_ICMP {
		t.Fatalf("protocol: got 0x%02x", ip.Protocol)
	}
	if ip.HeaderChecksum == 0 {
		t.Fatal("ipv4 checksum should be calculated by send path")
	}
	icmp := packemon.ParsedICMP(ip.Data)
	if icmp.Typ != 0x08 { // echo request
		t.Fatalf("icmp type: got 0x%02x", icmp.Typ)
	}
	if icmp.Checksum == 0 {
		t.Fatal("icmp checksum should be calculated by send path")
	}
}

func TestBuildDynamicForm_selectOrHex(t *testing.T) {
	// IPv4 の Protocol: 選択肢（ICMP/UDP/TCP）と16進数の自由入力の両立
	assembler := &packemon.ScratchIPv4Assembler{}

	t.Run("デフォルトは選択肢名で収集され名称変換される", func(t *testing.T) {
		_, collectValues := buildDynamicForm(assembler, "IPv4", "", nil)
		values := collectValues()
		if values["protocol"] != "ICMP" {
			t.Fatalf("protocol: got %v", values["protocol"])
		}
		ip, err := assembler.AssembleIPv4(values)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}
		if ip.Protocol != packemon.IPv4_PROTO_ICMP {
			t.Fatalf("protocol number: got 0x%02x", ip.Protocol)
		}
	})

	t.Run("選択肢に無いデフォルト値はCustom扱いで自由入力欄から収集される", func(t *testing.T) {
		// 例: OSPF(89=0x59) のような任意プロトコル番号
		_, collectValues := buildDynamicForm(assembler, "IPv4", "", map[string]string{"protocol": "0x59"})
		values := collectValues()
		if values["protocol"] != "0x59" {
			t.Fatalf("protocol: got %v", values["protocol"])
		}
		ip, err := assembler.AssembleIPv4(values)
		if err != nil {
			t.Fatalf("assemble: %v", err)
		}
		if ip.Protocol != 0x59 {
			t.Fatalf("protocol number: got 0x%02x", ip.Protocol)
		}
	})
}
