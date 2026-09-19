package packemon

import (
	"bytes"
	"strconv"
	"testing"
)

// defaultValuesForTest は、Assembler の Fields 定義のデフォルト値から values を作る
// （TUI の動的フォームをデフォルトのまま収集したのと同じ状態）。
func defaultValuesForTest(a Assembler, overrides map[string]any) map[string]any {
	values := map[string]any{}
	for _, spec := range a.Fields() {
		switch spec.Kind {
		case FieldKindCheckbox:
			b, _ := strconv.ParseBool(spec.Default)
			values[spec.Key] = b
		default:
			values[spec.Key] = spec.Default
		}
	}
	for k, v := range overrides {
		values[k] = v
	}
	return values
}

// フォームの apply が「構造体返却の固有メソッド（AssembleIPv4 等）」ではなく
// 「インターフェースの Assemble → Parsed* で構造体へ」を使っても、sender.packets に
// 入る構造体が同一（＝送信されるバイト列が同一）であることの全プロトコル保証。
//
// 自動計算フラグ（calc_*）は false に固定して比較する:
//   - 構造体版メソッドは常に「生値のまま」を返し、自動計算は送信経路（sendL3/L4）が
//     checkedCalc* フラグを見て行う
//   - バイト列版 Assemble はフラグ有効時に計算値を焼き込む（このとき payload=nil 前提の
//     値になるが、送信経路が同じフラグで再計算するため最終パケットは変わらない）
//
// つまりフラグ false 同士なら両経路は完全一致するはずで、それを検証する。
func TestAssembleThenParseRoundtrip_allProtocols(t *testing.T) {
	t.Run("IPv4", func(t *testing.T) {
		a := &ScratchIPv4Assembler{}
		values := defaultValuesForTest(a, map[string]any{"calc_total_length": false, "calc_checksum": false})
		want, err := a.AssembleIPv4(values)
		if err != nil {
			t.Fatalf("AssembleIPv4: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedIPv4(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("IPv6", func(t *testing.T) {
		a := &ScratchIPv6Assembler{}
		values := defaultValuesForTest(a, map[string]any{"calc_payload_length": false})
		want, err := a.AssembleIPv6(values)
		if err != nil {
			t.Fatalf("AssembleIPv6: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedIPv6(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("ICMP", func(t *testing.T) {
		a := &ScratchICMPAssembler{}
		values := defaultValuesForTest(a, map[string]any{"calc_checksum": false})
		want, err := a.AssembleICMP(values)
		if err != nil {
			t.Fatalf("AssembleICMP: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedICMP(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("TCP", func(t *testing.T) {
		a := &ScratchTCPAssembler{}
		values := defaultValuesForTest(a, nil)
		want, err := a.AssembleTCP(values)
		if err != nil {
			t.Fatalf("AssembleTCP: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedTCP(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("UDP", func(t *testing.T) {
		a := &ScratchUDPAssembler{}
		values := defaultValuesForTest(a, map[string]any{"calc_length": false})
		want, err := a.AssembleUDP(values)
		if err != nil {
			t.Fatalf("AssembleUDP: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedUDP(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("DNS", func(t *testing.T) {
		a := &ScratchDNSAssembler{}
		values := defaultValuesForTest(a, nil)
		want, err := a.AssembleDNS(values)
		if err != nil {
			t.Fatalf("AssembleDNS: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedDNSRequest(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %x\ngot : %x", want.Bytes(), got.Bytes())
		}
	})

	t.Run("HTTP", func(t *testing.T) {
		a := &ScratchHTTPAssembler{}
		values := defaultValuesForTest(a, nil)
		want, err := a.AssembleHTTP(values)
		if err != nil {
			t.Fatalf("AssembleHTTP: %v", err)
		}
		b, err := a.Assemble(values, nil)
		if err != nil {
			t.Fatalf("Assemble: %v", err)
		}
		got := ParsedHTTPRequest(b)
		if !bytes.Equal(want.Bytes(), got.Bytes()) {
			t.Fatalf("roundtrip mismatch\nwant: %q\ngot : %q", want.Bytes(), got.Bytes())
		}
	})
}
