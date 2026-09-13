package monitor

import (
	"strings"
	"testing"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

// findCellValue は FieldNodeView のテーブルから、タイトルが name の行の値を返す（インデント行含む）。
func findCellValue(t *testing.T, table *tview.Table, name string) string {
	t.Helper()
	for row := 0; row < table.GetRowCount(); row++ {
		if strings.TrimSpace(table.GetCell(row, 0).Text) == name {
			return strings.TrimSpace(table.GetCell(row, 1).Text)
		}
	}
	t.Fatalf("row %q not found", name)
	return ""
}

func TestIPv4ViewTableHexPrefix(t *testing.T) {
	ipv4 := &packemon.IPv4{
		Version:        0x04,
		Ihl:            0x05,
		Tos:            0x10,
		TotalLength:    64,
		Identification: 0x1234,
		Flags:          0x40,
		FragmentOffset: 0,
		Ttl:            64,
		Protocol:       packemon.IPv4_PROTO_TCP,
		HeaderChecksum: 0xabcd,
	}

	table := (&FieldNodeView{ipv4.FieldNode()}).viewTable()

	if got := findCellValue(t, table, "Total Length"); got != "64" {
		t.Fatalf("total length cell = %q, want %q", got, "64")
	}
	if got := findCellValue(t, table, "Protocol"); got != "0x6 (TCP)" {
		t.Fatalf("protocol cell = %q, want %q", got, "0x6 (TCP)")
	}
	if got := findCellValue(t, table, "Header Checksum"); got != "0xabcd" {
		t.Fatalf("header checksum cell = %q, want %q", got, "0xabcd")
	}
}

func TestTCPAndUDPViewTableHexPrefix(t *testing.T) {
	tcp := &packemon.TCP{
		SrcPort:        443,
		DstPort:        80,
		Sequence:       0x12345678,
		Acknowledgment: 0x90abcdef,
		HeaderLength:   0x50,
		Flags:          packemon.TCP_FLAGS_ACK,
		Window:         0x4000,
		Checksum:       0xbeef,
		UrgentPointer:  0,
		Options:        []byte{0x01, 0x01},
	}
	tcpTable := (&FieldNodeView{tcp.FieldNode()}).viewTable()

	if got := findCellValue(t, tcpTable, "Source Port"); got != "0x1bb (443)" {
		t.Fatalf("tcp src port cell = %q, want %q", got, "0x1bb (443)")
	}
	if got := findCellValue(t, tcpTable, "Sequence"); got != "0x12345678" {
		t.Fatalf("tcp sequence cell = %q, want %q", got, "0x12345678")
	}
	if got := findCellValue(t, tcpTable, "Flags"); !strings.HasPrefix(got, "0x10 ") {
		t.Fatalf("tcp flags cell = %q, want hex-prefixed flags", got)
	}

	udp := &packemon.UDP{
		SrcPort:  53,
		DstPort:  5353,
		Length:   0x24,
		Checksum: 0x1234,
	}
	udpTable := (&FieldNodeView{udp.FieldNode()}).viewTable()

	if got := findCellValue(t, udpTable, "Source Port"); got != "0x35 (53)" {
		t.Fatalf("udp src port cell = %q, want %q", got, "0x35 (53)")
	}
	if got := findCellValue(t, udpTable, "Length"); got != "36" {
		t.Fatalf("udp length cell = %q, want %q", got, "36")
	}
}

func TestDNSViewTableHexPrefix(t *testing.T) {
	dns := &packemon.DNS{
		TransactionID: 0x1337,
		Flags:         packemon.DNS_QR_RESPONSE,
		Questions:     1,
		AnswerRRs:     1,
		AuthorityRRs:  0,
		AdditionalRRs: 0,
		Queries: &packemon.Queries{
			Domain: []byte{0x03, 'w', 'w', 'w', 0x00},
			Typ:    packemon.DNS_QUERY_TYPE_A,
			Class:  packemon.DNS_QUERY_CLASS_IN,
		},
		Answers: []*packemon.Answer{
			{
				Name:       0xc00c,
				Typ:        packemon.DNS_QUERY_TYPE_A,
				Class:      packemon.DNS_QUERY_CLASS_IN,
				Ttl:        0x3c,
				DataLength: 4,
				Address:    0x01010101,
			},
		},
	}

	table := (&FieldNodeView{dns.FieldNode()}).viewTable()

	if got := findCellValue(t, table, "Transaction ID"); got != "0x1337" {
		t.Fatalf("dns transaction id cell = %q, want %q", got, "0x1337")
	}
	if got := findCellValue(t, table, "Flags"); !strings.HasPrefix(got, "0x8000 ") {
		t.Fatalf("dns flags cell = %q, want hex-prefixed flags", got)
	}
	if got := findCellValue(t, table, "Queries: Type"); got != "0x1 (A)" {
		t.Fatalf("dns query type cell = %q, want %q", got, "0x1 (A)")
	}
	if got := findCellValue(t, table, "TTL"); got != "0x3c" {
		t.Fatalf("dns answer ttl cell = %q, want %q", got, "0x3c")
	}
}
