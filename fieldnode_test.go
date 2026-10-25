package packemon

import (
	"encoding/hex"
	"testing"
)

func mustDecodeHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 想定外・不正なパケットでも、Monitor の詳細表示用の FieldNode 生成で panic しないこと
func TestFieldTreeFromPassive_notPanic(t *testing.T) {
	tests := []struct {
		name  string
		frame string
	}{
		{
			// ICMPv4 Port Unreachable（元パケット: UDP 1024 -> 53）
			name:  "icmpv4 error with original udp",
			frame: "ffffffffffff0211223344550800450000380000400040010000c0a80001c0a8000203030000000000004500002c0000400040110000c0a80001c0a800020400003500200000",
		},
		{
			// DNS クエリ（QNAME のラベル長 3 に対して実データが 1 バイト）
			name:  "dns query with invalid label length",
			frame: "ffffffffffff02112233445508004500002f0000400040110000c0a80001c0a8000230390035001b000012340100000100000000000003610000010001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passive := ParsedPacket(mustDecodeHex(t, tt.frame), true)
			_ = FieldTreeFromPassive(passive)
		})
	}
}

func TestOriginalICMPv4FieldNode(t *testing.T) {
	tests := []struct {
		name    string
		frame   string
		wantNil bool
	}{
		{
			// ICMPv4 Host Unreachable（元パケット: ICMPv4 Echo Request）
			name:    "original icmpv4",
			frame:   "ffffffffffff0211223344550800450000380000400040010000c0a80001c0a8000203010000000000004500001c0000400040010000c0a80001c0a800020800000034a10001",
			wantNil: false,
		},
		{
			// ICMPv4 Port Unreachable（元パケット: UDP 1024 -> 53）
			name:    "original udp",
			frame:   "ffffffffffff0211223344550800450000380000400040010000c0a80001c0a8000203030000000000004500002c0000400040110000c0a80001c0a800020400003500200000",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			passive := ParsedPacket(mustDecodeHex(t, tt.frame), true)
			if passive.ICMPv4Error == nil {
				t.Fatal("icmpv4 error should be parsed")
			}

			got := originalICMPv4FieldNode(passive.ICMPv4Error.OriginalIP)
			if (got == nil) != tt.wantNil {
				t.Fatalf("originalICMPv4FieldNode() = %v, wantNil %v", got, tt.wantNil)
			}
		})
	}
}

func TestDNS_DomainString(t *testing.T) {
	tests := []struct {
		name   string
		domain []byte
		want   string
	}{
		{
			name:   "go.dev",
			domain: []byte{0x02, 'g', 'o', 0x03, 'd', 'e', 'v', 0x00},
			want:   "go.dev.",
		},
		{
			name:   "label length exceeds data",
			domain: []byte{0x03, 'a', 0x00},
			want:   "",
		},
		{
			name:   "compression pointer",
			domain: []byte{0xc0, 0x0c, 0x00},
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &DNS{Queries: &Queries{Domain: tt.domain}}
			if got := d.DomainString(); got != tt.want {
				t.Fatalf("DomainString() = %q, want %q", got, tt.want)
			}
		})
	}
}

// go test -run '^$' -fuzz FuzzParsedPacket で、受信したパケットのパースから詳細表示用の FieldNode 生成までを検査する
func FuzzParsedPacket(f *testing.F) {
	for _, s := range []string{
		// ARP
		"ffffffffffff02112233445508060001080006040001021122334455c0a80001000000000000c0a80002",
		// IPv4 / UDP / DNS
		"ffffffffffff0211223344550800450000340000400040110000c0a80001c0a80002303900350020000012340100000100000000000002676f036465760000010001",
		// IPv4 / ICMPv4 Port Unreachable
		"ffffffffffff0211223344550800450000380000400040010000c0a80001c0a8000203030000000000004500002c0000400040110000c0a80001c0a800020400003500200000",
		// IPv6 / ICMPv6 Echo Request
		"333300000001021122334455" + "86dd" + "6000000000083a40" + "fe800000000000000000000000000001" + "ff020000000000000000000000000001" + "8000000000010001",
	} {
		b, err := hex.DecodeString(s)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		// 14 バイト未満のフレームは受信側（networkinterface_*.go）で除外している
		if len(b) < 14 {
			return
		}
		passive := ParsedPacket(b, true)
		_ = FieldTreeFromPassive(passive)
	})
}
