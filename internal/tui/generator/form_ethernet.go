package generator

import (
	"context"
	"fmt"
	"strings"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// ethernetForm は Ethernet の入力フォームを返す。
// Assembler の Fields 定義から動的に生成する。
// フォーム値は apply（sender.applyForms 経由、どのレイヤの送信でも直前に実行される）で
// sender の packets へ反映される。
func (g *generator) ethernetForm() *tview.Form {
	// Assembler インターフェースにのみ依存する（バックエンド差し替え可能）
	var assembler packemon.Assembler = &packemon.ScratchEthernetAssembler{}
	// var assembler packemon.Assembler = &packemon.GopacketEthernetAssembler{}
	// 自機/デフォルトルートの MAC は起動時に DEFAULT_* に設定される（cmd/packemon/main.go, init.go）
	ethernetForm, collectValues := buildDynamicForm(assembler, "Ethernet", "This section generates the Ethernet header.", map[string]string{
		"dst": DEFAULT_MAC_DESTINATION,
		"src": DEFAULT_MAC_SOURCE,
	})

	g.sender.registerApplyForm("Ethernet", func() error {
		// sender.packets は構造体（*packemon.EthernetHeader）を保持するため、
		// Assembler が返すバイト列をパースして構造体へ戻す（バックエンドに依らず共通の変換）
		b, err := assembler.Assemble(collectValues(), nil)
		if err != nil {
			return err
		}
		g.sender.packets.ethernet = packemon.ParsedEthernetFrame(b).Header
		return nil
	})

	ethernetForm.
		AddButton("Send!", func() {
			if err := g.sender.sendLayer2(context.TODO()); err != nil {
				g.addErrPage(err)
			}
		}).
		AddButton("Quit", func() {
			g.app.Stop()
		})

	return ethernetForm
}

// 以下は旧手書きフォームで使っていた MAC 入力バリデーション。
// 既存テスト（form_ethernet_test.go）の資産があるため残している。
// TODO: 動的フォームの入力中バリデーションに接続するか検討
type MACValidationResult struct {
	Address    packemon.HardwareAddr
	HasAddress bool // indicates whether Address contains a valid parsed address
	Valid      bool
	Error      string
}

// validateAndParseMACAddress validates and parses MAC address input
// Supports hex format (0x prefix), colon-separated, and dash-separated formats
func validateAndParseMACAddress(input string) MACValidationResult {
	l := len(input)

	if l > 20 {
		return MACValidationResult{
			Valid: false,
			Error: "MAC address too long (max 20 characters)",
		}
	}

	// Only try to parse when we have enough characters for a potential MAC address
	// Minimum: "0x" + 12 hex chars = 14, or XX:XX:XX:XX:XX:XX = 17, or XX-XX-XX-XX-XX-XX = 17
	if l >= 14 || ((strings.Contains(input, ":") || strings.Contains(input, "-")) && l >= 17) {
		var b []byte
		var err error

		if strings.Contains(input, ":") || strings.Contains(input, "-") {
			// Remove colons or dashes
			cleaned := strings.ReplaceAll(input, ":", "")
			cleaned = strings.ReplaceAll(cleaned, "-", "")

			if len(cleaned) > 12 {
				return MACValidationResult{
					Valid: false,
					Error: "Invalid MAC address format",
				}
			}

			// Validate hex characters
			for _, c := range cleaned {
				if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
					return MACValidationResult{
						Valid: true, // Allow continued typing
						Error: fmt.Sprintf("Invalid character: %c", c),
					}
				}
			}

			b, err = packemon.StrHexToBytes("0x" + cleaned)
		} else {
			b, err = packemon.StrHexToBytes(input)
		}

		if err != nil {
			return MACValidationResult{
				Valid: true, // Allow continued typing
				Error: "Invalid hex format",
			}
		}

		var addr packemon.HardwareAddr
		copy(addr[:], b)

		return MACValidationResult{
			Address:    addr,
			HasAddress: true,
			Valid:      true,
		}
	}

	return MACValidationResult{
		Valid: true, // Allow continued typing
	}
}
