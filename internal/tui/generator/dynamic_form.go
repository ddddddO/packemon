package generator

import (
	"fmt"
	"strconv"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

const dynamicFormFieldWidth = 20

// selectOrHexCustomOption は、FieldKindSelectOrHex の DropDown に追加する「自由入力を使う」選択肢。
const selectOrHexCustomOption = "Custom"

// selectOrHexCustomLabelSuffix は、FieldKindSelectOrHex のカスタム入力欄のラベルに付ける接尾辞。
const selectOrHexCustomLabelSuffix = " (custom hex)"

// buildDynamicForm は、Assembler の Fields 定義から入力フォームを自動生成する。
// 戻り値の collectValues は、フォームの現在値を Assembler.Assemble へ渡せる values として収集する。
//
// defaultOverrides は、FieldSpec の Default（静的なフォールバック値）を実行時の値で上書きする
// （キーは FieldSpec.Key）。自機の MAC/IP アドレスやデフォルトルートの IP 等、起動時に決まる
// 環境依存の初期値はここから注入する（既存の手書きフォームが DEFAULT_* 変数で行っていたのと同じ役割）。
//
// 既存の form_*.go はプロトコルごとに手書き（入力のたびに sender の packets へ直接反映）だが、
// この関数を使うと「Assembler を実装するだけでフォームが手に入る」ため、プロトコル追加時に
// フォームの手書きが不要になる。入力値の検証は Assemble 時にまとめて行われる
// （手書きフォームの入力中チェックの代わりに、送信時にエラーを返す方式）。
func buildDynamicForm(assembler packemon.Assembler, title string, description string, defaultOverrides map[string]string) (form *tview.Form, collectValues func() map[string]any) {
	form = tview.NewForm().
		AddTextView(title, description, 60, 3, true, false)

	specs := assembler.Fields()
	for _, spec := range specs {
		defaultValue := spec.Default
		if v, ok := defaultOverrides[spec.Key]; ok && v != "" {
			defaultValue = v
		}
		switch spec.Kind {
		case packemon.FieldKindCheckbox:
			defaultChecked, _ := strconv.ParseBool(defaultValue)
			form.AddCheckbox(spec.Label, defaultChecked, nil)
		case packemon.FieldKindSelect:
			initialOption := 0
			for i, o := range spec.Options {
				if o == defaultValue {
					initialOption = i
					break
				}
			}
			form.AddDropDown(spec.Label, spec.Options, initialOption, nil)
		case packemon.FieldKindSelectOrHex:
			// DropDown（選択肢 + Custom）とカスタム入力欄のペアで描画する。
			// DropDown で Custom を選ぶとカスタム入力欄の値（16進数の自由入力）が使われる
			options := append(append([]string{}, spec.Options...), selectOrHexCustomOption)
			initialOption := len(options) - 1 // defaultValue が選択肢に無ければ Custom
			customDefault := defaultValue
			for i, o := range spec.Options {
				if o == defaultValue {
					initialOption = i
					customDefault = ""
					break
				}
			}
			form.AddDropDown(spec.Label, options, initialOption, nil)
			form.AddInputField(spec.Label+selectOrHexCustomLabelSuffix, customDefault, dynamicFormFieldWidth, nil, nil)
		default: // FieldKindText / FieldKindHex
			form.AddInputField(spec.Label, defaultValue, dynamicFormFieldWidth, nil, nil)
		}
	}

	collectValues = func() map[string]any {
		values := map[string]any{}
		for _, spec := range specs {
			item := form.GetFormItemByLabel(spec.Label)
			if item == nil {
				continue
			}
			switch formItem := item.(type) {
			case *tview.InputField:
				values[spec.Key] = formItem.GetText()
			case *tview.Checkbox:
				values[spec.Key] = formItem.IsChecked()
			case *tview.DropDown:
				_, option := formItem.GetCurrentOption()
				if spec.Kind == packemon.FieldKindSelectOrHex && option == selectOrHexCustomOption {
					// Custom 選択時はカスタム入力欄の値を使う
					if custom, ok := form.GetFormItemByLabel(spec.Label + selectOrHexCustomLabelSuffix).(*tview.InputField); ok {
						values[spec.Key] = custom.GetText()
					}
					continue
				}
				values[spec.Key] = option
			}
		}
		return values
	}

	return form, collectValues
}

// boolFromValues は collectValues の結果から bool 値を取り出す（未指定は false）。
func boolFromValues(values map[string]any, key string) (bool, error) {
	v, ok := values[key]
	if !ok || v == nil {
		return false, nil
	}
	b, ok := v.(bool)
	if !ok {
		return false, fmt.Errorf("%s: unsupported type %T", key, v)
	}
	return b, nil
}
