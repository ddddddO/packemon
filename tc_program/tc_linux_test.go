//go:build linux
// +build linux

package tc_program

import (
	"testing"

	"github.com/cilium/ebpf/link"
)

func TestClose_nilLinks(t *testing.T) {
	// eBPF プログラムのアタッチに失敗した場合、link は nil のまま渡ってくる
	var linkEgress, linkIngress link.Link
	if err := Close(nil, linkEgress, linkIngress); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
