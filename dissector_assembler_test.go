package packemon

import (
	"bytes"
	"testing"
)

func TestScratchEthernetAssembler_Assemble(t *testing.T) {
	assembler := &ScratchEthernetAssembler{}

	payload := []byte{0xde, 0xad, 0xbe, 0xef}
	got, err := assembler.Assemble(map[string]any{
		"dst":        "00:15:5d:e2:c6:c6",
		"src":        "00:15:5d:6f:44:33",
		"ether_type": "0x0800",
	}, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 既存のスクラッチ実装（EthernetFrame.Bytes）と同一のバイト列になること
	want := NewEthernetFrame(
		HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		ETHER_TYPE_IPv4,
		payload,
	).Bytes()

	if !bytes.Equal(got, want) {
		t.Fatalf("assembled bytes mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestScratchEthernetAssembler_Assemble_invalidValues(t *testing.T) {
	assembler := &ScratchEthernetAssembler{}

	tests := []struct {
		name   string
		values map[string]any
	}{
		{name: "不正なMACアドレス", values: map[string]any{"dst": "invalid", "src": "00:15:5d:6f:44:33", "ether_type": "0x0800"}},
		{name: "不正なEtherType", values: map[string]any{"dst": "00:15:5d:e2:c6:c6", "src": "00:15:5d:6f:44:33", "ether_type": "zzz"}},
		{name: "値なし", values: map[string]any{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := assembler.Assemble(tt.values, nil); err == nil {
				t.Fatal("expected error, but got nil")
			}
		})
	}
}

func TestScratchARPAssembler_Assemble(t *testing.T) {
	assembler := &ScratchARPAssembler{}

	got, err := assembler.Assemble(map[string]any{
		"hardware_type": "0x0001",
		"protocol_type": "0x0800",
		"hardware_size": "0x06",
		"protocol_size": "0x04",
		"operation":     "0x0001",
		"sender_mac":    "00:15:5d:6f:44:33",
		"sender_ip":     "192.168.0.1",
		"target_mac":    "00:00:00:00:00:00",
		"target_ip":     "192.168.0.2",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 分解して往復（roundtrip）が成立すること
	arp := ParsedARP(got)
	if arp.Operation != 0x0001 {
		t.Fatalf("operation: got 0x%04x", arp.Operation)
	}
	if uint32ToIPv4Str(arp.SenderIPAddr) != "192.168.0.1" {
		t.Fatalf("sender ip: got %s", uint32ToIPv4Str(arp.SenderIPAddr))
	}
	if uint32ToIPv4Str(arp.TargetIPAddr) != "192.168.0.2" {
		t.Fatalf("target ip: got %s", uint32ToIPv4Str(arp.TargetIPAddr))
	}
}

func TestScratchIPv4Assembler_Assemble(t *testing.T) {
	assembler := &ScratchIPv4Assembler{}

	payload := []byte{0x01, 0x02, 0x03, 0x04}
	got, err := assembler.Assemble(map[string]any{
		"version":           "0x04",
		"ihl":               "0x05",
		"tos":               "0x00",
		"total_length":      "0x0000", // 自動計算で上書きされる
		"calc_total_length": true,
		"identification":    "0xe31f",
		"flags":             "0x40",
		"fragment_offset":   "0x0000",
		"ttl":               "0x80",
		"protocol":          "0x01",
		"checksum":          "0x0000",
		"calc_checksum":     true,
		"src":               "192.168.0.1",
		"dst":               "192.168.0.2",
	}, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := ParsedIPv4(got)
	if ip.StrSrcIPAddr() != "192.168.0.1" || ip.StrDstIPAddr() != "192.168.0.2" {
		t.Fatalf("addr: got %s -> %s", ip.StrSrcIPAddr(), ip.StrDstIPAddr())
	}
	// 自動計算: ヘッダ20バイト + payload 4バイト
	if ip.TotalLength != 24 {
		t.Fatalf("total length: got %d, want 24", ip.TotalLength)
	}
	if ip.HeaderChecksum == 0 {
		t.Fatal("checksum should be calculated")
	}
	if !bytes.Equal(ip.Data, payload) {
		t.Fatalf("payload mismatch: %x", ip.Data)
	}
}

func TestScratchIPv4Assembler_Assemble_calcOffで不正な値のまま送れる(t *testing.T) {
	assembler := &ScratchIPv4Assembler{}

	got, err := assembler.Assemble(map[string]any{
		"version": "0x04", "ihl": "0x05", "tos": "0x00",
		"total_length": "0xffff", "calc_total_length": false,
		"identification": "0xe31f", "flags": "0x40", "fragment_offset": "0x0000",
		"ttl": "0x80", "protocol": "0x01",
		"checksum": "0x1234", "calc_checksum": false,
		"src": "192.168.0.1", "dst": "192.168.0.2",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := ParsedIPv4(got)
	if ip.TotalLength != 0xffff {
		t.Fatalf("total length should be kept: got 0x%04x", ip.TotalLength)
	}
	if ip.HeaderChecksum != 0x1234 {
		t.Fatalf("checksum should be kept: got 0x%04x", ip.HeaderChecksum)
	}
}

func TestScratchICMPv4Assembler_Assemble(t *testing.T) {
	assembler := &ScratchICMPv4Assembler{}

	got, err := assembler.Assemble(map[string]any{
		"type": "0x08", "code": "0x00",
		"checksum": "0x0000", "calc_checksum": true,
		"identifier": "0x34a1", "sequence": "0x0001",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 既存実装（NewICMPv4: 同じ値でchecksum自動計算）と同一バイト列になること
	want := NewICMPv4().Bytes()
	if !bytes.Equal(got, want) {
		t.Fatalf("assembled bytes mismatch\n got: %x\nwant: %x", got, want)
	}
}

func TestScratchTCPAssembler_Assemble(t *testing.T) {
	assembler := &ScratchTCPAssembler{}

	got, err := assembler.Assemble(map[string]any{
		"src_port": "47000", "dst_port": "80",
		"sequence": "0x1f6e9499", "acknowledgment": "0x00000000",
		"header_length": "0x50", "flags": "0x02",
		"window": "0xfaf0", "checksum": "0x0000", "urgent_pointer": "0x0000",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tcp := ParsedTCP(got)
	if tcp.SrcPort != 47000 || tcp.DstPort != 80 {
		t.Fatalf("port: got %d -> %d", tcp.SrcPort, tcp.DstPort)
	}
	if tcp.Sequence != 0x1f6e9499 {
		t.Fatalf("sequence: got 0x%08x", tcp.Sequence)
	}
	if uint8(tcp.Flags) != 0x02 { // SYN
		t.Fatalf("flags: got 0x%02x", uint8(tcp.Flags))
	}
}

func TestScratchUDPAssembler_Assemble(t *testing.T) {
	assembler := &ScratchUDPAssembler{}

	payload := []byte{0xca, 0xfe}
	got, err := assembler.Assemble(map[string]any{
		"src_port": "47000", "dst_port": "53",
		"length": "0x0000", "calc_length": true,
		"checksum": "0x0000",
	}, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	udp := ParsedUDP(got)
	if udp.SrcPort != 47000 || udp.DstPort != 53 {
		t.Fatalf("port: got %d -> %d", udp.SrcPort, udp.DstPort)
	}
	// 自動計算: ヘッダ8バイト + payload 2バイト
	if udp.Length != 10 {
		t.Fatalf("length: got %d, want 10", udp.Length)
	}
}

func TestScratchIPv6Assembler_Assemble(t *testing.T) {
	assembler := &ScratchIPv6Assembler{}

	payload := []byte{0x01, 0x02, 0x03}
	got, err := assembler.Assemble(map[string]any{
		"version": "0x06", "traffic_class": "0x00", "flow_label": "0x00000",
		"payload_length": "0x0000", "calc_payload_length": true,
		"next_header": "0x3a", "hop_limit": "0x40",
		"src": "2001:db8::1", "dst": "2001:db8::2",
	}, payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ip := ParsedIPv6(got)
	if ip.StrSrcIPAddr() != "2001:db8::1" || ip.StrDstIPAddr() != "2001:db8::2" {
		t.Fatalf("addr: got %s -> %s", ip.StrSrcIPAddr(), ip.StrDstIPAddr())
	}
	if ip.PayloadLength != 3 {
		t.Fatalf("payload length: got %d, want 3", ip.PayloadLength)
	}
}

func TestAssembler_Fields(t *testing.T) {
	// 全 Assembler が TUI フォーム自動生成に必要な定義（Key/Label）を持つこと
	assemblers := map[string]Assembler{
		"ethernet": &ScratchEthernetAssembler{},
		"arp":      &ScratchARPAssembler{},
		"ipv4":     &ScratchIPv4Assembler{},
		"ipv6":     &ScratchIPv6Assembler{},
		"icmpv4":   &ScratchICMPv4Assembler{},
		"tcp":      &ScratchTCPAssembler{},
		"udp":      &ScratchUDPAssembler{},
		"dns":      &ScratchDNSAssembler{},
		"http":     &ScratchHTTPAssembler{},
	}
	for name, a := range assemblers {
		t.Run(name, func(t *testing.T) {
			fields := a.Fields()
			if len(fields) == 0 {
				t.Fatal("fields must not be empty")
			}
			for _, f := range fields {
				if f.Key == "" || f.Label == "" {
					t.Fatalf("field must have key and label: %+v", f)
				}
			}
		})
	}
}

func TestScratchDissector_Dissect(t *testing.T) {
	// Ethernet + IPv4 + ICMPv4 のフレームを既存実装で組み立てて、Dissector で分解できること
	ipv4 := NewIPv4(IPv4_PROTO_ICMPv4, 0xc0a80001, 0xc0a80002) // 192.168.0.1 -> 192.168.0.2
	ipv4.Data = NewICMPv4().Bytes()
	frame := NewEthernetFrame(
		HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		ETHER_TYPE_IPv4,
		ipv4.Bytes(),
	)

	dissector := &ScratchDissector{}
	ft, err := dissector.Dissect(frame.Bytes())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	assertChildValue(t, eth, "Type", "0x0800")

	ip, ok := nodeByName["IPv4"]
	if !ok {
		t.Fatalf("IPv4 node not found: %+v", ft.Nodes)
	}
	assertChildValue(t, ip, "Source Address", "192.168.0.1")
	assertChildValue(t, ip, "Destination Address", "192.168.0.2")

	icmpv4, ok := nodeByName["ICMPv4"]
	if !ok {
		t.Fatalf("ICMPv4 node not found: %+v", ft.Nodes)
	}
	assertChildValue(t, icmpv4, "Type", "0x08")
}

func TestScratchDissector_Dissect_shortFrame(t *testing.T) {
	dissector := &ScratchDissector{}
	// パース不能な短いバイト列でも panic せずエラーになること
	if _, err := dissector.Dissect([]byte{0x00, 0x01}); err == nil {
		t.Fatal("expected error, but got nil")
	}
}

func assertChildValue(t *testing.T, node *FieldNode, name, want string) {
	t.Helper()
	for _, c := range node.Children {
		if c.Name == name {
			if c.Value != want {
				t.Fatalf("%s/%s: got %q, want %q", node.Name, name, c.Value, want)
			}
			return
		}
	}
	t.Fatalf("%s: child %q not found", node.Name, name)
}

func TestScratchEthernetAssembler_Assemble_dot1q(t *testing.T) {
	assembler := &ScratchEthernetAssembler{}

	got, err := assembler.Assemble(map[string]any{
		"dst":          "00:15:5d:e2:c6:c6",
		"src":          "00:15:5d:6f:44:33",
		"ether_type":   "Dot1Q", // Select の選択肢名でも指定できる
		"dot1q_fields": "0x0123",
		"dot1q_type":   "0x0800",
	}, []byte{0x01})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ef := ParsedEthernetFrame(got)
	if ef.Header.Typ != ETHER_TYPE_DOT1Q {
		t.Fatalf("type: got 0x%04x", ef.Header.Typ)
	}
	if ef.Header.Dot1QFiels == nil || ef.Header.Dot1QFiels.Dot1QFiels != 0x0123 {
		t.Fatalf("dot1q fields: got %+v", ef.Header.Dot1QFiels)
	}
}

func TestScratchDNSAssembler_Assemble(t *testing.T) {
	assembler := &ScratchDNSAssembler{}

	got, err := assembler.Assemble(map[string]any{
		"transaction_id": "0xaa78", "flags": "0x0100",
		"questions": "0x0001", "answer_rrs": "0x0000",
		"authority_rrs": "0x0000", "additional_rrs": "0x0000",
		"query_domain": "go.dev", "query_type": "0x0001", "query_class": "0x0001",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// ヘッダ12バイト + "go.dev" のラベルエンコード（1+2+1+3+1=8バイト） + type/class 4バイト
	if len(got) != 12+8+4 {
		t.Fatalf("length: got %d", len(got))
	}
	// ラベルエンコードの確認: 02 67 6f 03 64 65 76 00 ( 2"go" 3"dev" 0 )
	wantDomain := []byte{0x02, 'g', 'o', 0x03, 'd', 'e', 'v', 0x00}
	if !bytes.Equal(got[12:20], wantDomain) {
		t.Fatalf("domain: got %x, want %x", got[12:20], wantDomain)
	}
}

func TestScratchHTTPAssembler_Assemble(t *testing.T) {
	assembler := &ScratchHTTPAssembler{}

	got, err := assembler.Assemble(map[string]any{
		"method": "GET", "uri": "/", "version": "HTTP/1.1",
		"host": "github.com", "user_agent": "packemon", "accept": "*/*",
	}, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	s := string(got)
	if !bytes.HasPrefix(got, []byte("GET / HTTP/1.1")) {
		t.Fatalf("request line: got %q", s[:min(40, len(s))])
	}
	for _, want := range []string{"Host: github.com", "User-Agent: packemon", "Accept: */*"} {
		if !bytes.Contains(got, []byte(want)) {
			t.Fatalf("missing header %q in %q", want, s)
		}
	}
}

func TestParsedPacket_ipv6TCP(t *testing.T) {
	// IPv6 上の TCP がパースされること（かつては IPv6 の TCP ケースが無く IPv6 止まりだった）
	tcp := &TCP{SrcPort: 47000, DstPort: 443, HeaderLength: 0x50}
	ipv6 := &IPv6{
		Version: 6, NextHeader: IPv6_NEXT_HEADER_TCP, HopLimit: 64,
		SrcAddr: make([]byte, 16), DstAddr: make([]byte, 16),
		Data: tcp.Bytes(),
	}
	frame := NewEthernetFrame(
		HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		ETHER_TYPE_IPv6,
		ipv6.Bytes(),
	)

	passive := ParsedPacket(frame.Bytes(), true)
	if passive.IPv6 == nil {
		t.Fatal("ipv6 should be parsed")
	}
	if passive.TCP == nil {
		t.Fatal("tcp over ipv6 should be parsed")
	}
	if passive.TCP.DstPort != 443 {
		t.Fatalf("dst port: got %d", passive.TCP.DstPort)
	}
}

func TestParsedPacket_dot1qARP(t *testing.T) {
	// VLANタグ付き ARP がパースされること（かつては Dot1Q 内に ARP ケースが無く Ethernet 止まりだった）
	arp := &ARP{HardwareType: 0x0001, ProtocolType: 0x0800, HardwareAddrLength: 6, ProtocolLength: 4, Operation: 0x0001}
	frame := &EthernetFrame{
		Header: &EthernetHeader{
			Dst:        HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			Src:        HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
			Typ:        ETHER_TYPE_DOT1Q,
			Dot1QFiels: &EthernetDot1QFields{Dot1QFiels: 0x0001, Type: ETHER_TYPE_ARP},
		},
		Data: arp.Bytes(),
	}

	passive := ParsedPacket(frame.Bytes(), true)
	if passive.ARP == nil {
		t.Fatal("arp under dot1q should be parsed")
	}
	if passive.ARP.Operation != 0x0001 {
		t.Fatalf("operation: got 0x%04x", passive.ARP.Operation)
	}
}

func TestParsedPacket_failSoft(t *testing.T) {
	// 上位層のパースに失敗しても、そこまでの層は返ること（fail-soft）
	ipv4 := NewIPv4(IPv4_PROTO_UDP, 0xc0a80001, 0xc0a80002)
	ipv4.Data = []byte{0x00} // UDPとしては短すぎるペイロード → ParsedUDP が panic する
	frame := NewEthernetFrame(
		HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		ETHER_TYPE_IPv4,
		ipv4.Bytes(),
	)

	passive := ParsedPacket(frame.Bytes(), true)
	if passive == nil || passive.EthernetFrame == nil {
		t.Fatal("ethernet should be returned")
	}
	if passive.IPv4 == nil {
		t.Fatal("ipv4 should be returned even when upper layer parsing fails")
	}
	if passive.UDP != nil {
		t.Fatal("udp should not be parsed from too short payload")
	}
}
