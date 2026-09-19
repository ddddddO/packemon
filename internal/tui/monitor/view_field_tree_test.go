package monitor

import (
	"strings"
	"testing"

	"github.com/ddddddO/packemon"
)

func TestFieldNodeView_viewTable(t *testing.T) {
	frame := packemon.NewEthernetFrame(
		packemon.HardwareAddr{0x00, 0x15, 0x5d, 0xe2, 0xc6, 0xc6},
		packemon.HardwareAddr{0x00, 0x15, 0x5d, 0x6f, 0x44, 0x33},
		packemon.ETHER_TYPE_IPv4,
		nil,
	)

	table := (&FieldNodeView{frame.FieldNode()}).viewTable()

	// Ethernet の3フィールドが行として描画されること
	if got := table.GetRowCount(); got != 3 {
		t.Fatalf("row count: got %d, want 3", got)
	}
	if title := table.GetCell(1, 0).Text; !strings.Contains(title, "Source") {
		t.Fatalf("row1 title: got %q", title)
	}
	if value := table.GetCell(1, 1).Text; !strings.Contains(value, "00:15:5d:6f:44:33") {
		t.Fatalf("row1 value: got %q", value)
	}
}

func TestFieldNodeView_viewTable_nested(t *testing.T) {
	// DNS の Answer（入れ子ノード）がインデントされて描画されること
	dns := &packemon.DNS{
		Queries: &packemon.Queries{Typ: packemon.DNS_QUERY_TYPE_A, Class: packemon.DNS_QUERY_CLASS_IN},
		Answers: []*packemon.Answer{
			{Typ: packemon.DNS_QUERY_TYPE_A, Class: packemon.DNS_QUERY_CLASS_IN, Address: 0xc0a80001},
		},
	}
	dns.Domain("go.dev")

	table := (&FieldNodeView{dns.FieldNode()}).viewTable()

	// ヘッダ9行 + Answer 1行 + Answer 配下6行（Name/Type/Class/TTL/Data length/Address）
	if got := table.GetRowCount(); got != 9+1+6 {
		t.Fatalf("row count: got %d, want 16", got)
	}
	// Answer 配下はインデントされている
	if title := table.GetCell(10, 0).Text; !strings.Contains(title, "   Name") {
		t.Fatalf("nested title should be indented: got %q", title)
	}
	// Address が IPv4 表記を含む
	if value := table.GetCell(15, 1).Text; !strings.Contains(value, "192.168.0.1") {
		t.Fatalf("address value: got %q", value)
	}
}
