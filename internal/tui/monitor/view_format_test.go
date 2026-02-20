package monitor

import (
	"strings"
	"testing"

	"github.com/ddddddO/packemon"
)

func normalizedCellText(text string) string {
	return strings.TrimSpace(text)
}

func TestIPv4ViewTableHexPrefix(t *testing.T) {
	view := &IPv4{
		IPv4: &packemon.IPv4{
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
		},
	}

	table := view.viewTable()

	if got := normalizedCellText(table.GetCell(0, 1).Text); got != "0x4" {
		t.Fatalf("version cell = %q, want %q", got, "0x4")
	}
	if got := normalizedCellText(table.GetCell(3, 1).Text); got != "64" {
		t.Fatalf("total length cell = %q, want %q", got, "64")
	}
	if got := normalizedCellText(table.GetCell(8, 1).Text); got != "0x6 (TCP)" {
		t.Fatalf("protocol cell = %q, want %q", got, "0x6 (TCP)")
	}
	if got := normalizedCellText(table.GetCell(9, 1).Text); got != "0xabcd" {
		t.Fatalf("header checksum cell = %q, want %q", got, "0xabcd")
	}
}

func TestTCPAndUDPViewTableHexPrefix(t *testing.T) {
	tcpView := &TCP{
		TCP: &packemon.TCP{
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
		},
	}
	tcpTable := tcpView.viewTable()

	if got := normalizedCellText(tcpTable.GetCell(0, 1).Text); got != "0x1bb (443)" {
		t.Fatalf("tcp src port cell = %q, want %q", got, "0x1bb (443)")
	}
	if got := normalizedCellText(tcpTable.GetCell(2, 1).Text); got != "0x12345678" {
		t.Fatalf("tcp sequence cell = %q, want %q", got, "0x12345678")
	}
	if got := normalizedCellText(tcpTable.GetCell(5, 1).Text); got != "0x10" {
		t.Fatalf("tcp flags cell = %q, want %q", got, "0x10")
	}

	udpView := &UDP{
		UDP: &packemon.UDP{
			SrcPort:  53,
			DstPort:  5353,
			Length:   0x24,
			Checksum: 0x1234,
		},
	}
	udpTable := udpView.viewTable()

	if got := normalizedCellText(udpTable.GetCell(0, 1).Text); got != "0x35 (53)" {
		t.Fatalf("udp src port cell = %q, want %q", got, "0x35 (53)")
	}
	if got := normalizedCellText(udpTable.GetCell(2, 1).Text); got != "0x24" {
		t.Fatalf("udp length cell = %q, want %q", got, "0x24")
	}
}

func TestDNSViewTableHexPrefix(t *testing.T) {
	view := &DNS{
		DNS: &packemon.DNS{
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
		},
	}

	table := view.viewTable()

	if got := normalizedCellText(table.GetCell(0, 1).Text); got != "0x1337" {
		t.Fatalf("dns transaction id cell = %q, want %q", got, "0x1337")
	}
	if got := normalizedCellText(table.GetCell(1, 1).Text); !strings.HasPrefix(got, "0x8000 ") {
		t.Fatalf("dns flags cell = %q, want hex-prefixed flags", got)
	}
	if got := normalizedCellText(table.GetCell(7, 1).Text); got != "0x1 (A)" {
		t.Fatalf("dns query type cell = %q, want %q", got, "0x1 (A)")
	}
	if got := normalizedCellText(table.GetCell(13, 1).Text); got != "0x3c" {
		t.Fatalf("dns answer ttl cell = %q, want %q", got, "0x3c")
	}
}
