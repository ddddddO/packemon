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
	}
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
