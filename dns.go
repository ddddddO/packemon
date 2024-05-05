package packemon

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// https://atmarkit.itmedia.co.jp/ait/articles/1601/29/news014.html
// 上記とパケットキャプチャ見てイメージがつく、domain
type DNS struct {
	TransactionID uint16
	Flags         uint16
	Questions     uint16
	AnswerRRs     uint16
	AuthorityRRs  uint16
	AdditionalRRs uint16
	Queries       *Queries
}

type Queries struct {
	Domain []uint8
	Typ    uint16
	Class  uint16
}

func (d *DNS) Domain(domain string) {
	splited := strings.Split(domain, ".")
	buf := make([]uint8, len(domain)+2)

	cnt := 0
	for _, s := range splited {
		buf[cnt] = uint8(len(s))
		cnt++
		for _, c := range s {
			buf[cnt] = uint8(rune(c)) // ドメインに絵文字とか使えた気が。そうするとバグるはず
			cnt++
		}
	}

	buf[len(domain)+1] = 0x00
	d.Queries.Domain = buf
}

func (d *DNS) Bytes() []byte {
	var buf bytes.Buffer
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.TransactionID)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.Flags)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.Questions)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.AnswerRRs)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.AuthorityRRs)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.AdditionalRRs)
	buf.Write(b)

	buf.Write(d.Queries.Domain)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.Queries.Typ)
	buf.Write(b)

	b = make([]byte, 2)
	binary.BigEndian.PutUint16(b, d.Queries.Class)
	buf.Write(b)

	return buf.Bytes()
}
