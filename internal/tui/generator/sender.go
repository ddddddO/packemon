package generator

import (
	"context"
	"fmt"
	"runtime/debug"
	"time"

	"github.com/ddddddO/packemon"
)

type sender struct {
	selectedProtocolByLayer map[string]string
	packets                 *packets
	sendFn                  func(*packemon.EthernetFrame) error

	// applyForms は、動的フォーム（buildDynamicForm）の現在値を packets へ反映する関数群。
	// 旧手書きフォームは入力のたびに packets へ直接反映していたが、動的フォームは送信時に
	// まとめて反映するため、どのレイヤの送信でも直前に全フォームぶん実行する（send 冒頭）。
	// これにより上位レイヤ（TLS/DNS等）の送信時にも下位フォームの最新値が使われる。
	applyForms map[string]func() error
}

func newSender(packets *packets, sendFn func(*packemon.EthernetFrame) error) *sender {
	selectedProtocolByLayer := map[string]string{}
	selectedProtocolByLayer["L7"] = "DNS"
	selectedProtocolByLayer["L5/6"] = ""
	selectedProtocolByLayer["L4"] = "UDP"
	selectedProtocolByLayer["L3"] = "IPv4"
	selectedProtocolByLayer["L2"] = "Ethernet"

	return &sender{
		selectedProtocolByLayer: selectedProtocolByLayer,
		packets:                 packets,
		sendFn:                  sendFn,
		applyForms:              map[string]func() error{},
	}
}

// registerApplyForm は、動的フォームの「現在値を packets へ反映する」関数を登録する。
func (s *sender) registerApplyForm(name string, apply func() error) {
	s.applyForms[name] = apply
}

func (s *sender) sendLayer2(ctx context.Context) error {
	return s.send(ctx, "L2")
}

func (s *sender) sendLayer3(ctx context.Context) error {
	return s.send(ctx, "L3")
}

func (s *sender) sendLayer4(ctx context.Context) error {
	return s.send(ctx, "L4")
}

func (s *sender) sendLayer7(ctx context.Context) error {
	return s.send(ctx, "L7")
}

const TIMEOUT = 5000 * time.Millisecond

func (s *sender) send(ctx context.Context, currentLayer string) (err error) {
	defer func() {
		if e := recover(); e != nil {
			trace := debug.Stack()
			err = fmt.Errorf("Panic!!\n%v\nstack trace\n%s\n", e, string(trace))
		}
	}()

	// 動的フォームの現在値を packets へ反映する（旧手書きフォームの「入力のたびに反映」の代替）
	for name, apply := range s.applyForms {
		if err := apply(); err != nil {
			return fmt.Errorf("%s form: %w", name, err)
		}
	}

	// selectedL2 := s.selectedProtocolByLayer["L2"] // 今、固定でイーサネットだからコメントアウト
	selectedL3 := s.selectedProtocolByLayer["L3"]
	selectedL4 := s.selectedProtocolByLayer["L4"]
	selectedL5_6 := s.selectedProtocolByLayer["L5/6"]
	selectedL7 := s.selectedProtocolByLayer["L7"]

	ctx, cancel := context.WithTimeout(ctx, TIMEOUT)
	defer cancel()

	switch currentLayer {
	case "L2":
		return s.sendL2(ctx)
	case "L3":
		return s.sendL3(ctx, selectedL3)
	case "L4":
		return s.sendL4(ctx, selectedL4, selectedL3)
	case "L5/6":
		return s.sendL5_6(ctx, selectedL5_6, selectedL4, selectedL3)
	case "L7":
		return s.sendL7(ctx, selectedL7, selectedL5_6, selectedL4, selectedL3)
	default:
		return fmt.Errorf("unsupported layer")
	}
}
