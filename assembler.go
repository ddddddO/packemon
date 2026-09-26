package packemon

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Assembler は、1プロトコル分のフィールド値からバイト列を組み立てるバックエンドの抽象。
// Generator は、この抽象を通すことで実装（scratch / gopacket 等）を差し替えられるようにする。
// 実装の命名は「実装方式 + プロトコル名 + Assembler」とする（例: ScratchEthernetAssembler、
// 将来の GopacketEthernetAssembler）。各プロトコルの実装はそのプロトコルのファイル
// （例: ethernet.go）に置く。
//
// Fields はTUIフォームを自動生成するためのフィールド定義を返す。
// Assemble は Fields のキーに対応する値と、上位レイヤのバイト列（payload）を受け取り、
// このプロトコルのヘッダを付与したバイト列を返す。
// ※ レイヤを下位から順に包んでいく（スタック連結）ために、上位レイヤの結果を
//
//	payload 引数として明示的に受ける。
type Assembler interface {
	Fields() []FieldSpec
	Assemble(values map[string]any, payload []byte) ([]byte, error)
}

// FieldKind は、TUIフォームでの入力部品の種類。
type FieldKind int

const (
	// FieldKindText は自由入力（MACアドレスやIPアドレス等、書式は Assembler 側で検証）
	FieldKindText FieldKind = iota
	// FieldKindHex は16進数入力（例: 0x0800）
	FieldKindHex
	// FieldKindSelect は Options からの選択
	FieldKindSelect
	// FieldKindSelectOrHex は Options からの選択に加えて16進数の自由入力もできる
	// （TUI では DropDown ＋ カスタム入力欄のペアとして描画される）
	FieldKindSelectOrHex
	// FieldKindCheckbox はオン/オフ
	FieldKindCheckbox
)

// FieldSpec は、Assembler が受け付ける1フィールドの定義。TUIフォーム自動生成に使う。
type FieldSpec struct {
	Key     string    // Assemble の values のキー
	Label   string    // フォームに表示するラベル
	Kind    FieldKind //
	Default string    // 初期値（表示用文字列）
	Options []string  // Kind == FieldKindSelect のときの選択肢
}

// 以下、Assembler 実装が values の値を既存スクラッチ実装の型へ変換するための共通ヘルパー。

// hardwareAddrFromValue は "00:11:22:33:44:55" 形式（net.ParseMAC が受ける形式）または
// "0x001122334455" 形式（既存の手書きフォームの入力形式）の文字列、
// または HardwareAddr そのものを受け付ける。
func hardwareAddrFromValue(v any) (HardwareAddr, error) {
	switch value := v.(type) {
	case HardwareAddr:
		return value, nil
	case string:
		if strings.HasPrefix(value, "0x") {
			b, err := StrHexToBytes(value)
			if err != nil {
				return HardwareAddr{}, err
			}
			return HardwareAddr(b), nil
		}
		mac, err := net.ParseMAC(value)
		if err != nil {
			return HardwareAddr{}, err
		}
		if len(mac) != 6 {
			return HardwareAddr{}, fmt.Errorf("invalid mac addr length: %d", len(mac))
		}
		return HardwareAddr(mac), nil
	default:
		return HardwareAddr{}, fmt.Errorf("unsupported type: %T", v)
	}
}

// uint8FromValue は "0x08" 等の文字列（strconv.ParseUint の base=0 が受ける形式）、
// または uint8 そのものを受け付ける。
func uint8FromValue(v any) (uint8, error) {
	switch value := v.(type) {
	case uint8:
		return value, nil
	case string:
		n, err := strconv.ParseUint(value, 0, 8)
		if err != nil {
			return 0, err
		}
		return uint8(n), nil
	default:
		return 0, fmt.Errorf("unsupported type: %T", v)
	}
}

// uint16FromValue は "0x0800" や "47000" 等の文字列、または uint16 そのものを受け付ける。
func uint16FromValue(v any) (uint16, error) {
	switch value := v.(type) {
	case uint16:
		return value, nil
	case string:
		n, err := strconv.ParseUint(value, 0, 16)
		if err != nil {
			return 0, err
		}
		return uint16(n), nil
	default:
		return 0, fmt.Errorf("unsupported type: %T", v)
	}
}

// uint32FromValue は "0x1f6e9499" 等の文字列、または uint32 そのものを受け付ける。
func uint32FromValue(v any) (uint32, error) {
	switch value := v.(type) {
	case uint32:
		return value, nil
	case string:
		n, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return 0, err
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("unsupported type: %T", v)
	}
}

func bytesFromValue(v any) ([]byte, error) {
	switch value := v.(type) {
	case []byte:
		return value, nil
	case string:
		trimed := strings.TrimPrefix(strings.TrimPrefix(value, "0x"), "0X")
		if len(trimed)%2 != 0 {
			trimed = "0" + trimed
		}
		return hex.DecodeString(trimed)
	default:
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
}

// ipv4AddrFromValue は "192.168.0.1" 形式の文字列、または uint32 そのものを受け付ける。
func ipv4AddrFromValue(v any) (uint32, error) {
	switch value := v.(type) {
	case uint32:
		return value, nil
	case string:
		ip := net.ParseIP(value)
		if ip == nil || ip.To4() == nil {
			return 0, fmt.Errorf("invalid ipv4 addr: %q", value)
		}
		b := ip.To4()
		return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
	default:
		return 0, fmt.Errorf("unsupported type: %T", v)
	}
}

// ipv6AddrFromValue は "2001:db8::1" 形式の文字列、または16バイトの []byte を受け付ける。
func ipv6AddrFromValue(v any) ([]byte, error) {
	switch value := v.(type) {
	case []byte:
		if len(value) != 16 {
			return nil, fmt.Errorf("invalid ipv6 addr length: %d", len(value))
		}
		return value, nil
	case string:
		ip := net.ParseIP(value)
		if ip == nil || ip.To16() == nil {
			return nil, fmt.Errorf("invalid ipv6 addr: %q", value)
		}
		return ip.To16(), nil
	default:
		return nil, fmt.Errorf("unsupported type: %T", v)
	}
}

// stringFromValue は string を受け付ける（HTTP のメソッド名やDNSのドメイン名等、自由文字列用）。
func stringFromValue(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("unsupported type: %T", v)
}

// boolFromValue は bool、または "true"/"false" 等（strconv.ParseBool が受ける形式）を受け付ける。
// 値が未指定（nil）の場合は false。
func boolFromValue(v any) (bool, error) {
	switch value := v.(type) {
	case nil:
		return false, nil
	case bool:
		return value, nil
	case string:
		return strconv.ParseBool(value)
	default:
		return false, fmt.Errorf("unsupported type: %T", v)
	}
}
