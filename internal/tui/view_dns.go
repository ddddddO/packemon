package tui

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/ddddddO/packemon"
	"github.com/rivo/tview"
)

type DNS struct {
	*packemon.DNS
}

func (*DNS) rows() int {
	return 19
}

func (*DNS) columns() int {
	return 30
}

func (d *DNS) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" DNS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tview.NewTableCell(padding("Transaction ID")))
	table.SetCell(0, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.TransactionID))))

	table.SetCell(1, 0, tview.NewTableCell(padding("Flags")))
	table.SetCell(1, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Flags, d.bytesToFlags()))))

	table.SetCell(2, 0, tview.NewTableCell(padding("Questions")))
	table.SetCell(2, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", d.Questions, d.Questions))))

	table.SetCell(3, 0, tview.NewTableCell(padding("AnswerRRs")))
	table.SetCell(3, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", d.AnswerRRs, d.AnswerRRs))))

	table.SetCell(4, 0, tview.NewTableCell(padding("AuthorityRRs")))
	table.SetCell(4, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", d.AuthorityRRs, d.AuthorityRRs))))

	table.SetCell(5, 0, tview.NewTableCell(padding("AdditionalRRs")))
	table.SetCell(5, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%d)", d.AdditionalRRs, d.AdditionalRRs))))

	table.SetCell(6, 0, tview.NewTableCell(padding("Queries: Domain")))
	table.SetCell(6, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Queries.Domain, d.bytesToDomain()))))

	table.SetCell(7, 0, tview.NewTableCell(padding("Queries: Type")))
	table.SetCell(7, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Queries.Typ, d.bytesToQueryType()))))

	table.SetCell(8, 0, tview.NewTableCell(padding("Queries: Class")))
	table.SetCell(8, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Queries.Class, d.bytesToQueryClass()))))

	if len(d.Answers) > 0 {
		table.SetCell(9, 0, tview.NewTableCell(padding("Answers: Name")))
		// Wireshark上ではクエリドメイン名が補完で表示されてるよう。多分、Answer.Name はQuery.Domainのエイリアスなのかな
		table.SetCell(9, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Answers[0].Name, d.bytesToDomain()))))

		table.SetCell(10, 0, tview.NewTableCell(padding("Answers: Type")))
		table.SetCell(10, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Answers[0].Typ))))

		table.SetCell(11, 0, tview.NewTableCell(padding("Answers: Class")))
		table.SetCell(11, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Answers[0].Class))))

		table.SetCell(12, 0, tview.NewTableCell(padding("Answers: TTL")))
		table.SetCell(12, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Answers[0].Ttl))))

		table.SetCell(13, 0, tview.NewTableCell(padding("Answers: Data length")))
		table.SetCell(13, 1, tview.NewTableCell(padding(fmt.Sprintf("%x", d.Answers[0].DataLength))))

		table.SetCell(14, 0, tview.NewTableCell(padding("Answers: Address")))
		switch d.Answers[0].Typ {
		case packemon.DNS_QUERY_TYPE_A:
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, d.Answers[0].Address)
			table.SetCell(14, 1, tview.NewTableCell(padding(fmt.Sprintf("%x (%s)", d.Answers[0].Address, net.IPv4(b[0], b[1], b[2], b[3]).String()))))
		case packemon.DNS_QUERY_TYPE_AAAA:
			// TODO: ipv6用のDNSクエリのレスポンスちょっとv4と違ってる、あとで
		}
	}

	return table
}

// TODO: ここはあまりいじらないように
//
//	大本の DNS struct の Flags フィールドを struct に変更するかも
func (d *DNS) bytesToFlags() string {
	switch {
	case packemon.IsDNSRequest(d.Flags):
		return "Standard query"
	case packemon.IsDNSResponse(d.Flags):
		return "Standard query response"
	default:
		return "-"
	}

}

func (d *DNS) bytesToDomain() string {
	s := ""
	for _, b := range d.Queries.Domain {
		if b == 0x00 {
			return s
		}
		if b == 0x03 {
			s += "."
			continue
		}

		s += string(b)
	}
	return s
}

// TODO:
func (d *DNS) bytesToQueryType() string {
	switch d.Queries.Typ {
	case packemon.DNS_QUERY_TYPE_A:
		return "A"
	case packemon.DNS_QUERY_TYPE_AAAA:
		return "AAAA"
	default:
		return "-"
	}
}

func (d *DNS) bytesToQueryClass() string {
	switch d.Queries.Class {
	case packemon.DNS_QUERY_CLASS_IN:
		return "IN"
	default:
		return "-"
	}
}
