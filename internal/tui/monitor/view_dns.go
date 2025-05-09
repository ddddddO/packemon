package monitor

import (
	"encoding/binary"
	"net"

	"github.com/ddddddO/packemon"
	"github.com/ddddddO/packemon/internal/tui"
	"github.com/rivo/tview"
)

type DNS struct {
	*packemon.DNS
}

func (d *DNS) rows() int {
	return 19 + (len(d.Answers) * 7)
}

func (*DNS) columns() int {
	return 30
}

func (d *DNS) viewTable() *tview.Table {
	table := tview.NewTable().SetBorders(false)
	table.Box = tview.NewBox().SetBorder(true).SetTitle(" DNS Header ").SetTitleAlign(tview.AlignLeft).SetBorderPadding(1, 1, 1, 1)

	table.SetCell(0, 0, tui.TableCellTitle("Transaction ID"))
	table.SetCell(0, 1, tui.TableCellContent("%x", d.TransactionID))

	table.SetCell(1, 0, tui.TableCellTitle("Flags"))
	table.SetCell(1, 1, tui.TableCellContent("%x (%s)", d.Flags, d.bytesToFlags()))

	table.SetCell(2, 0, tui.TableCellTitle("Questions"))
	table.SetCell(2, 1, tui.TableCellContent("%x (%d)", d.Questions, d.Questions))

	table.SetCell(3, 0, tui.TableCellTitle("AnswerRRs"))
	table.SetCell(3, 1, tui.TableCellContent("%x (%d)", d.AnswerRRs, d.AnswerRRs))

	table.SetCell(4, 0, tui.TableCellTitle("AuthorityRRs"))
	table.SetCell(4, 1, tui.TableCellContent("%x (%d)", d.AuthorityRRs, d.AuthorityRRs))

	table.SetCell(5, 0, tui.TableCellTitle("AdditionalRRs"))
	table.SetCell(5, 1, tui.TableCellContent("%x (%d)", d.AdditionalRRs, d.AdditionalRRs))

	table.SetCell(6, 0, tui.TableCellTitle("Queries: Domain"))
	table.SetCell(6, 1, tui.TableCellContent("%x (%s)", d.Queries.Domain, d.bytesToDomain()))

	table.SetCell(7, 0, tui.TableCellTitle("Queries: Type"))
	table.SetCell(7, 1, tui.TableCellContent("%x (%s)", d.Queries.Typ, d.bytesToQueryType()))

	table.SetCell(8, 0, tui.TableCellTitle("Queries: Class"))
	table.SetCell(8, 1, tui.TableCellContent("%x (%s)", d.Queries.Class, d.bytesToQueryClass()))

	for i, answer := range d.Answers {
		position := (i + 1) * 9
		table.SetCell(position, 0, tui.TableCellTitle("Answer"))

		table.SetCell(position+1, 0, tui.TableCellTitle("   Name"))
		// Wireshark上ではクエリドメイン名が補完で表示されてるよう。多分、Answer.Name はQuery.Domainのエイリアスなのかな
		table.SetCell(position+1, 1, tui.TableCellContent("%x (%s)", answer.Name, d.bytesToDomain()))

		table.SetCell(position+2, 0, tui.TableCellTitle("   Type"))
		table.SetCell(position+2, 1, tui.TableCellContent("%x", answer.Typ))

		table.SetCell(position+3, 0, tui.TableCellTitle("   Class"))
		table.SetCell(position+3, 1, tui.TableCellContent("%x", answer.Class))

		table.SetCell(position+4, 0, tui.TableCellTitle("   TTL"))
		table.SetCell(position+4, 1, tui.TableCellContent("%x", answer.Ttl))

		table.SetCell(position+5, 0, tui.TableCellTitle("   Data length"))
		table.SetCell(position+5, 1, tui.TableCellContent("%x", answer.DataLength))

		table.SetCell(position+6, 0, tui.TableCellTitle("   Address"))
		switch answer.Typ {
		case packemon.DNS_QUERY_TYPE_A:
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, answer.Address)
			table.SetCell(position+6, 1, tui.TableCellContent("%x (%s)", answer.Address, net.IPv4(b[0], b[1], b[2], b[3]).String()))
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
	for i := 0; i < len(d.Queries.Domain); {
		b := d.Queries.Domain[i]
		charCnt := int(b)

		for j := 0; j < charCnt; j++ {
			i++
			s += string(d.Queries.Domain[i])
		}
		i++

		if b == 0x00 {
			return s
		}
		s += "."
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
